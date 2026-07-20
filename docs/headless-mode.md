# Non-interactive Mode

Use `scripts/run-headless.sh` to run assessments from a shell, CI job, or scheduled task. The wrapper handles authentication, cost and duration limits, and exit codes.

The same command works for local repositories, AppSec-managed scans, and CI pipelines.

## Contents

- [Choose a workflow](#decision-matrix)
- [Minimal CI example](#minimal-example)
- [Prerequisites](#prerequisites)
- [Part A — Non-interactive local & ops runs](#part-a)
  - [A1. Scan your own repository](#a1-scan-your-own-repository)
  - [A2. AppSec team scans an external repository](#a2-appsec-team-scans-an-external-repository)
  - [A3. Cost-limited / time-capped assessments](#a3-cost-limited--time-capped-assessments)
  - [A4. Requirements compliance check (standalone)](#a4-requirements-compliance-check-standalone)
  - [A5. Thorough assessment](#a5-full-featured-assessment)
- [Part B — CI/CD pipelines](#part-b)
  - [B1. Cadence — when to run in CI](#b1-cadence)
  - [B2. Cost & duration planning](#b2-cost--duration-planning)
  - [B3. GitHub Actions](#b3-github-actions)
  - [B4. GitLab CI](#b4-gitlab-ci)
  - [B5. Jenkins](#b5-jenkins)
  - [B6. Pull-request gating (`--pr-mode --fail-on`)](#b6-pr-gating)
  - [B7. CI cache: `--restore-from` for incremental runs](#b7-ci-cache)
- [Authentication in non-interactive mode](#authentication)
- [Security and permissions](#security-and-permissions)
- [Exit codes and CI semantics](#exit-codes)
- [Output files](#output-files)
- [Flag reference](#flag-reference)
- [Troubleshooting](#troubleshooting)
- [Deprecated flags](#deprecated-flags)

<a id="decision-matrix"></a>

## Choose a workflow

Each row links to the section covering that scenario.

| Goal | Section |
|---|---|
| Scan the repository you are developing | [A1](#a1-scan-your-own-repository) |
| Scan another team's repository without writing to it | [A2](#a2-appsec-team-scans-an-external-repository) |
| Set cost and runtime limits | [A3](#a3-cost-limited--time-capped-assessments) |
| Run a requirements audit | [A4](#a4-requirements-compliance-check-standalone) |
| Run a thorough assessment | [A5](#a5-full-featured-assessment) |
| Add a scheduled CI scan | [B3](#b3-github-actions), [B4](#b4-gitlab-ci), or [B5](#b5-jenkins) |
| Gate a pull request on new findings | [B6](#b6-pr-gating) |

<a id="minimal-example"></a>

## Minimal CI example

This example runs an incremental assessment with cost and duration limits and writes SARIF:

```bash
./scripts/run-headless.sh \
  --incremental \
  --max-duration 1800 \
  --max-budget 5 \
  --sarif
```

- `--incremental` analyzes components affected by recent changes.
- `--max-duration 1800` stops after 30 minutes.
- `--max-budget 5` stops when estimated API cost reaches $5.
- `--sarif` writes `threat-model.sarif.json`.

## Prerequisites

1. **Claude Code CLI** installed and on your `PATH` ([installation guide](https://claude.ai/download)).
2. **Authentication** — one of:
   - **API key** (per-token billing): `export ANTHROPIC_API_KEY="sk-ant-..."` — recommended for CI. Use `--max-budget` to cap spend.
   - **Subscription** (Claude Pro / Team / Enterprise): run `claude auth login` first. Works locally; **does not work in a non-TTY CI runner** — see [Authentication in non-interactive mode](#authentication).
3. The plugin repository cloned locally (or installed into `~/.claude/plugins/`).

The script auto-detects billing mode from `ANTHROPIC_API_KEY`. When API billing is active without `--max-budget`, a warning is printed.

<a id="part-a"></a>

## Part A — Non-interactive local & ops runs

These examples run from a developer or AppSec shell.

<a id="a1-scan-your-own-repository"></a>

### A1. Scan your own repository

Developer workflow: run the full assessment from your repo root. Output lands in `docs/security/` by default:

```bash
# Full threat model of the current repo
cd /path/to/my-project
/path/to/appsec-advisor/scripts/run-headless.sh

# Add a SARIF export for downstream tooling (YAML is emitted by default)
/path/to/appsec-advisor/scripts/run-headless.sh --sarif

# Dry-run first to preview scope and estimated complexity
/path/to/appsec-advisor/scripts/run-headless.sh --dry-run

# Analyze only affected components after code changes
/path/to/appsec-advisor/scripts/run-headless.sh --incremental
```

Result: `docs/security/threat-model.md` (+ `.yaml`, `.sarif.json` when requested). YAML is always emitted unless `--no-yaml` is passed, because subsequent incremental runs need it as baseline.

<a id="a2-appsec-team-scans-an-external-repository"></a>

### A2. AppSec team scans an external repository

Analyze another repository and write the results to a separate AppSec directory:

```bash
# Output in the team's own docs/security/
./scripts/run-headless.sh --repo /repos/team-frontend

# Output written to a central AppSec directory (target repo stays untouched)
./scripts/run-headless.sh \
  --repo /repos/team-frontend \
  --output /appsec-reports/team-frontend

# Dated output directory for audit trail
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api/2026-04-08 \
  --sarif

# Incremental review after the team pushed changes
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --incremental

# Preview scope before committing budget
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --dry-run
```

When `--output` points outside the target repository, the assessment does not write to that repository.

<a id="a3-cost-limited--time-capped-assessments"></a>

### A3. Cost-limited / time-capped assessments

`--max-budget` limits API spend; `--max-duration` limits wall-clock time. A stopped run can be continued with `--resume`.

```bash
# Preview scope before committing to a full run
./scripts/run-headless.sh --repo /repos/large-monorepo --dry-run

# Cap API spend at $3
./scripts/run-headless.sh --repo /repos/small-service --max-budget 3

# Cap at $8 with full exports + requirements
./scripts/run-headless.sh \
  --repo /repos/large-monorepo \
  --sarif --requirements \
  --max-budget 8

# Combined cap: 10 USD or 40 min, whichever hits first
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --sarif --requirements \
  --max-budget 10 \
  --max-duration 2400
```

When either limit is reached, the run writes a checkpoint:

```bash
# Budget ran out mid-run — resume from the last checkpoint
./scripts/run-headless.sh \
  --repo /repos/large-monorepo \
  --max-budget 5 \
  --resume
```

<a id="a4-requirements-compliance-check-standalone"></a>

### A4. Requirements compliance check (standalone)

Run the `audit-security-requirements` skill to verify security requirements against a codebase — without running a full STRIDE analysis:

```bash
# All requirements
./scripts/run-headless.sh --audit-requirements

# Filter to a single category
./scripts/run-headless.sh --audit-requirements --category SEC-AUTH

# Save the report (Markdown + PDF + JSON)
./scripts/run-headless.sh --audit-requirements --save-report

# External repo
./scripts/run-headless.sh --audit-requirements --repo /repos/team-frontend --save-report

# Combined: threat model with requirements AND a standalone requirements report
./scripts/run-headless.sh --repo /repos/team-api --requirements --sarif
./scripts/run-headless.sh --audit-requirements --repo /repos/team-api --save-report
```

The command prints each open requirement with evidence and remediation. `--save-report` also writes Markdown, PDF, and JSON reports under `docs/security/`.

<a id="a5-full-featured-assessment"></a>

### A5. Thorough assessment

This example uses thorough depth, Opus reasoning, a custom requirements catalog, and verbose progress:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-payment-api \
  --output /appsec-reports/team-payment-api/2026-04-09 \
  --assessment-depth thorough \
  --reasoning-model opus \
  --sarif \
  --requirements https://security.example.com/appsec-requirements.yaml \
  --max-budget 15 \
  --verbose
```

Thorough and Opus runs cost more than the default. See [cost and duration planning](#b2-cost--duration-planning) and use `--dry-run` before setting the budget for a new repository.

Verbose mode streams progress and cost data from `$OUTPUT_DIR/.agent-run.log` and `$OUTPUT_DIR/.hook-events.log`.

<a id="part-b"></a>

## Part B — CI/CD pipelines

Everything in Part B assumes non-TTY execution with an `ANTHROPIC_API_KEY` secret. For interactive / local runs, use Part A.

<a id="b1-cadence"></a>

### B1. Cadence — when to run in CI

Full assessments are too slow and expensive for every push. Use narrow incremental checks on pull requests and schedule full scans separately.

| Trigger | Recommendation | Typical mode |
|---|---|---|
| Every push on main branch | Not recommended | — |
| Every pull request | Only with `--pr-mode --incremental --fail-on high` (narrow delta) | PR delta |
| PR labeled `security-review` | Recommended — manual trigger with full scan | `--full` |
| Nightly / weekly schedule | Recommended — rolling full scan | `--full --sarif` |
| Release pipeline | Recommended — blocking on Critical | `--full --fail-on critical` |
| `workflow_dispatch` (manual) | Recommended — when reviewer requests | any mode |

An incremental run with no relevant changes is inexpensive, but it only establishes that the change introduced no new findings. Keep a periodic full scan.

<a id="b2-cost--duration-planning"></a>

### B2. Cost & duration planning

Clean runs against OWASP Juice Shop measured on 2026-06-23 cost about USD 18 for quick, USD 31 for standard, and USD 50 for thorough. Wall-clock time was 43, 88, and 94 minutes respectively. Repository size, stack, model choice, pricing, and cache state can change those figures substantially.

In the same standard benchmark, full Opus reasoning cost $40.78 compared with $30.01 for `sonnet-economy`. Incremental scans commonly reduce token use by 70–90% when a valid baseline exists.

Use `--dry-run` for a new repository and set `--max-budget` and `--max-duration` on every CI job. The [Threat Modeler cost section](threat-modeler.md#assessment-depth--cost-control) contains the full comparison and model overrides.

<a id="b3-github-actions"></a>

### B3. GitHub Actions

```yaml
# .github/workflows/threat-model.yml
name: Threat Model Assessment
on:
  schedule:
    - cron: '0 2 * * 1'       # Weekly Monday 02:00 UTC
  workflow_dispatch:          # Manual trigger for ad-hoc reviews

jobs:
  threat-model:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      security-events: write  # needed for SARIF upload
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0       # incremental/baseline needs history

      - name: Install Claude Code
        run: npm install -g @anthropic-ai/claude-code

      - name: Clone AppSec Plugin
        run: git clone https://github.com/your-org/appsec-advisor.git /tmp/appsec-advisor

      # Restore prior run artifacts so incremental has a baseline
      - name: Restore baseline
        uses: actions/cache@v4
        with:
          path: docs/security
          key: threat-model-${{ github.ref_name }}
          restore-keys: threat-model-

      - name: Run Threat Model
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          /tmp/appsec-advisor/scripts/run-headless.sh \
            --incremental \
            --sarif \
            --max-duration 2400 \
            --max-budget 5

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: docs/security/threat-model.sarif.json

      - name: Upload threat model as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: threat-model
          path: docs/security/threat-model.*
```

For a **requirements-only** job (faster, cheaper), swap the main step for:

```yaml
      - name: Check Requirements
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          /tmp/appsec-advisor/scripts/run-headless.sh \
            --audit-requirements \
            --save-report \
            --max-budget 3
```

<a id="b4-gitlab-ci"></a>

### B4. GitLab CI

```yaml
# .gitlab-ci.yml (excerpt)
threat-model:
  image: node:20
  stage: security
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_PIPELINE_SOURCE == "web"'       # manual trigger
  variables:
    GIT_DEPTH: 0
  cache:
    key: "threat-model-$CI_COMMIT_REF_SLUG"
    paths:
      - docs/security/
  before_script:
    - npm install -g @anthropic-ai/claude-code
    - git clone https://gitlab.example.com/appsec/appsec-advisor.git /tmp/appsec-advisor
  script:
    - /tmp/appsec-advisor/scripts/run-headless.sh
        --incremental
        --sarif
        --max-duration 2400
        --max-budget 5
  artifacts:
    when: always
    paths:
      - docs/security/threat-model.md
      - docs/security/threat-model.yaml
      - docs/security/threat-model.sarif.json
    reports:
      sast: docs/security/threat-model.sarif.json   # surfaced in MR security tab
```

<a id="b5-jenkins"></a>

### B5. Jenkins

```groovy
pipeline {
  agent { label 'linux' }
  triggers { cron('H 2 * * 1') }              // weekly Monday ~02:00
  environment {
    ANTHROPIC_API_KEY = credentials('anthropic-api-key')
  }
  stages {
    stage('Install') {
      steps {
        sh 'npm install -g @anthropic-ai/claude-code'
        sh 'git clone https://github.com/your-org/appsec-advisor.git /tmp/appsec-advisor'
      }
    }
    stage('Threat Model') {
      steps {
        sh '''
          /tmp/appsec-advisor/scripts/run-headless.sh \
            --incremental --sarif \
            --max-duration 2400 --max-budget 5
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'docs/security/threat-model.*', allowEmptyArchive: true
      recordIssues(tools: [sarif(pattern: 'docs/security/threat-model.sarif.json')])
    }
  }
}
```

<a id="b6-pr-gating"></a>

### B6. Pull-request gating (`--pr-mode --fail-on`)

`--pr-mode` produces a focused *delta* report for a merge request: implies `--incremental`, uses `--base <ref>` (set it to the PR's target branch, e.g. `origin/main`) to compute the diff, and emits only threats introduced in the PR.

`--fail-on <level>` turns the result into a build gate — the script exits non-zero when the delta contains at least one threat at or above `<level>` (`critical` | `high` | `medium`).

```bash
./scripts/run-headless.sh \
  --pr-mode \
  --base origin/main \
  --fail-on high \
  --max-duration 600 \
  --max-budget 2 \
  --sarif
```

Typical PR pipeline usage:

```yaml
# GitHub Actions — PR-triggered gate
on:
  pull_request:
    branches: [main]

jobs:
  threat-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: npm install -g @anthropic-ai/claude-code
      - run: git clone https://github.com/your-org/appsec-advisor.git /tmp/appsec-advisor
      - env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          /tmp/appsec-advisor/scripts/run-headless.sh \
            --pr-mode --base origin/${{ github.base_ref }} \
            --fail-on high --max-duration 600 --max-budget 2 \
            --sarif
```

Choose the threshold based on your review policy and observed false-positive rate.

<a id="b7-ci-cache"></a>

### B7. CI cache: `--restore-from` for incremental runs

Incremental runs need a prior `threat-model.yaml` as baseline. In CI the workspace is clean on every run, so pull the baseline from CI cache or from a previous pipeline's artifacts:

```bash
# Pull a prior artifact into the expected location before running
./scripts/run-headless.sh \
  --restore-from ./prior-run/docs/security/ \
  --incremental \
  --sarif \
  --max-budget 3
```

You can also restore `docs/security/` with the CI provider's cache, as shown in the GitHub and GitLab examples.

<a id="authentication"></a>

## Authentication in non-interactive mode

Headless runs support API-key and subscription authentication:

| Mode | How to activate | Works in TTY terminal | Works in CI runner (non-TTY) |
|---|---|---|---|
| API key (per-token) | `export ANTHROPIC_API_KEY=sk-ant-...` | Yes | **Yes** — per-token billing; use `--max-budget` to cap spend |
| Subscription — interactive login | `claude auth login` — stores refresh token in `~/.claude/` | Yes | **No** — `auth login` needs a browser |
| Subscription — OAuth token | `claude setup-token` (once, in a browser) → `export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...` | Yes | **Yes** — non-interactive subscription billing for CI |

Two ways to run unattended:

- **API key** — inject `ANTHROPIC_API_KEY` as a CI secret. Per-token billing, decoupled from any personal quota, rotatable, and `--max-budget` applies.
- **Subscription OAuth token** — generate once with `claude setup-token` and store the `sk-ant-oat01-…` value as a CI secret exposed as `CLAUDE_CODE_OAUTH_TOKEN`. The run bills against the subscription (draws on its rate limit). When this variable is set the script skips the interactive-login preflight (`claude auth status` only reflects stored credentials and would false-negative on a fresh runner). Do **not** also set `ANTHROPIC_API_KEY` — it takes precedence and would switch billing to per-token.

Interactive `claude auth login` stores a browser-obtained refresh token in `~/.claude/` and is for local/TTY use only.

<a id="security-and-permissions"></a>

## Security and permissions

The headless script bypasses interactive permission prompts and uses a fixed tool allow-list. Only run it against repositories you trust or inside an isolated environment.

**Data sent to the API.** Files read during analysis are sent to the Anthropic API. Review [SECURITY.md](../SECURITY.md#data-sent-to-anthropic-api) before scanning repositories with sensitive content.

**Write scope.** Writes are limited to `$OUTPUT_DIR` (default `<repo>/docs/security/`). Set `--output` to a separate directory to keep the target repository unchanged.

**Credentials.** `ANTHROPIC_API_KEY` is read from the environment and forwarded to the Claude Code CLI; it never lands in any log or output file. No other authentication material is expected.

**Logging.** `.agent-run.log` and `.hook-events.log` include paths, token counts, and cost estimates, but not prompt or response bodies. Restrict access to `$OUTPUT_DIR` if repository paths are sensitive.

**Concurrency.** `.appsec-lock` prevents overlapping runs against the same output directory.

**Claude Code permissions.** Headless runs require the tool allow-list to be written into the target repository before the first run. Use `make setup-target REPO=<path>` (or `/appsec-advisor:check-permissions` inside a CC session) to write `.claude/settings.local.json` into the target repo (pass `SCOPE=project` to write `.claude/settings.json` instead).

<a id="exit-codes"></a>

## Exit codes and CI semantics

The script propagates the `claude` CLI exit code, plus `--fail-on` overlay:

| Code | Meaning | What a CI should do |
|---|---|---|
| 0 | Assessment completed; no gate-violating findings | Upload SARIF + artifacts; continue pipeline |
| 1 | Assessment failed (agent error, lock conflict, missing prerequisites) | Fail build; surface `.agent-run.log` as artifact |
| 2 | Budget or duration cap reached before completion | Warn; schedule a `--resume` job |
| 20 | `--fail-on <level>` matched — delta contains findings at or above threshold | Fail build; require manual security review |

In most pipelines, map exit code `1` to pipeline failure and `2` to warning-with-resume; `20` is the expected signal for a working PR gate.

<a id="output-files"></a>

## Output files

All files are written to `$OUTPUT_DIR` (default: `<repo>/docs/security/`):

| File | When created | Purpose |
|---|---|---|
| `threat-model.md` | Always | Human-readable threat model report |
| `threat-model.yaml` | Always (unless `--no-yaml`) | Machine-readable export; baseline for incremental runs |
| `threat-model.sarif.json` | `--sarif` | SARIF v2.1.0 for code scanning upload |
| `appsec-requirements-report.md` / `.pdf` / `.json` | `--audit-requirements --save-report` | Requirements compliance report |
| `.agent-run.log` | Always | Progress and errors |
| `.hook-events.log` | Always | Token and cost events |
| `.appsec-cache/baseline.json` | Always | Baseline for incremental assessments |

Other dotfiles in the output directory are intermediate run data. Do not publish or edit them.

<a id="flag-reference"></a>

## Flag reference

Not every `create-threat-model` flag is accepted by the wrapper. This table lists everything `run-headless.sh` exposes today.

### Scope & targeting

| Flag | Purpose |
|---|---|
| `--repo <path>` | Repository to analyze (default: current working directory) |
| `--output <path>` | Output directory (default: `<repo>/docs/security`) |
| `--incremental` | Analyze only components affected by recent changes and carry forward prior findings |
| `--full` | Force full scan even when prior output exists |
| `--base <ref>` | Git ref to diff `HEAD` against (default: commit SHA recorded in prior `threat-model.yaml`) |
| `--pr-mode` | Focused delta report for MR/PR (implies `--incremental`) |
| `--dry-run` | Preview scope without running the full pipeline |
| `--resume` | Continue from last checkpoint |
| `--restore-from <path>` | Restore `$OUTPUT_DIR` from a prior run before starting |

### Output formats

| Flag | Purpose |
|---|---|
| `--yaml` | (no-op — YAML is written by default) |
| `--no-yaml` | Suppress `threat-model.yaml` — **breaks incremental mode** |
| `--sarif` | Also write `threat-model.sarif.json` (SARIF v2.1.0) |
| `--json` | Return structured JSON output on stdout (useful for piping into CI steps) |
| `--verbose` | Stream real-time hook event log on stderr |

### Analysis scope

| Flag | Purpose |
|---|---|
| `--assessment-depth quick\|standard\|thorough` | Control coverage, analysis depth, runtime, and cost; see [Threat Modeler](threat-modeler.md#assessment-depth--cost-control) |
| `--evidence-verifier-cap <N>` | Verify at most `N` non-Critical findings in Phase 10a; Critical findings do not count toward the cap and are selected first. Defaults: 20 quick, 30 standard, 100 thorough. |
| `--register-severity-floor critical\|high\|medium\|low\|informational` | Keep only findings at or above this effective severity in the canonical report and its SARIF/pentest-task exports; default `medium` excludes Low and Informational findings |
| `--requirements [<url>]` | Enable the requirements compliance check during the assessment |
| `--no-requirements` | Skip requirements even when enabled in config |

### Models

| Flag | Purpose |
|---|---|
| `--model <model>` | Session (main-loop) model. **Defaults to `claude-sonnet-4-6` (economy)** — the biggest cost lever; it drives cache-read cost and the alias-following agents (renderer, abuse-verifier, orchestrator, content-QA). Override per run with an explicit id. |
| `--reasoning-model <tier>` | Reasoning tier for STRIDE/triage/merger: `opus`, `opus-cheap`, `sonnet`, `sonnet-economy` |

The session-model default is where headless runs get their ~half-cost economy automatically. Buy back quality per stage with `--triage-model claude-sonnet-5` and the `APPSEC_RENDERER_MODEL` / `APPSEC_ABUSE_VERIFIER_MODEL` env vars — see *Session Model* in `docs/threat-modeler.md`.

### Gates & caps

| Flag | Purpose |
|---|---|
| `--max-duration <sec>` | Abort the run if it exceeds the given wall-clock duration |
| `--max-budget <usd>` | Stop when estimated cost exceeds this amount |
| `--fail-on critical\|high\|medium` | Exit code 20 when delta contains threats at or above `<level>` |
| `--no-qa` | Skip model-based QA; structural validation still runs |

### Housekeeping

| Flag | Purpose |
|---|---|
| `--clean-cache` | Delete cache & transient files in `$OUTPUT_DIR`; keeps the threat model. Exits without running. |
| `--clean-all` | Delete everything in `$OUTPUT_DIR` (interactive confirm unless `--force` / `CI=true`). Exits without running. |
| `--force` | Skip the interactive confirmation for `--clean-all` |

### Skill selection

| Flag | Purpose |
|---|---|
| `--audit-requirements` | Run `audit-security-requirements` instead of the threat model |
| `--check-requirements` | Deprecated alias for `--audit-requirements` (see [Deprecated flags](#deprecated-flags)) |
| `--category <filter>` | Category filter for requirements check (e.g. `SEC-AUTH`) |
| `--save-report` | Save requirements report (Markdown + PDF + JSON) |

<a id="troubleshooting"></a>

## Troubleshooting

**"No credentials found" / `claude auth login` prompt in CI.**
The pipeline is trying to use subscription auth with no credentials on the runner. Either set `ANTHROPIC_API_KEY` (per-token billing) or `CLAUDE_CODE_OAUTH_TOKEN` (subscription billing, from `claude setup-token`) as a CI secret and pass it through as env (e.g. `env: CLAUDE_CODE_OAUTH_TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}` in GitHub Actions). See [Authentication in non-interactive mode](#authentication).

**Incremental scan keeps doing a full scan.**
Incremental needs `threat-model.yaml` from a prior run as baseline. In CI, the workspace is clean every run — restore the prior `docs/security/` via CI cache or `--restore-from`. See [B7](#b7-ci-cache). Also check that you are not passing `--no-yaml` earlier in the pipeline — that breaks the baseline.

**`.appsec-lock` exists and blocks the run.**
A previous run may still be active, or it crashed after writing a fresh heartbeat. `run-headless.sh --resume` now checks `$OUTPUT_DIR` before starting `claude -p` and refuses with the inspected path when an active lock is present. First verify you are using the same `--output` as the interrupted run; `--repo /path/to/repo` defaults to `/path/to/repo/docs/security`, which is not the same as `--output /path/to/repo`. If no assessment is running, inspect or clean the state with `python3 scripts/check_state.py "$OUTPUT_DIR" --clean`.

**Script exits with code 2 "budget exhausted" in the middle of a run.**
This is expected when the cap is reached. Re-run with `--resume` on the same `$OUTPUT_DIR`, or raise `--max-budget`.

**GitHub Actions: SARIF upload silently skipped.**
The job needs `permissions: security-events: write` and the workflow needs `contents: read` or `write`. Without those, the upload step is a no-op.

**Relative `--output` path resolves to the plugin directory, not the repo.**
Pass absolute paths for `--output` when working from a different directory, or run from the repo root. The wrapper resolves relative paths against the current working directory at invocation time, not against `--repo`.

**Run starts, but no progress for >5 minutes.**
Enable `--verbose` to tail `.agent-run.log` on stderr. The recon scan is typically the longest silent phase on large repos. If it is stuck >10 min, abort with Ctrl-C and rerun with `--dry-run` to check the recon scope.

**"timeout: command not found" warning when `--max-duration` is set.**
The wrapper uses GNU `timeout` for `--max-duration`. On Alpine, install it with `apk add coreutils` or omit the duration limit.

**PR gate fires on threats that already existed in main.**
Use `--pr-mode` instead of plain `--incremental`; `--pr-mode` scopes the delta against `--base` and filters out pre-existing findings.

<a id="deprecated-flags"></a>

## Deprecated flags

Still accepted for backward compatibility; will print a deprecation warning:

| Deprecated | Use instead |
|---|---|
| `--check-requirements` | `--audit-requirements` |
| `--with-requirements` | `--requirements` |
| `--ignore-requirements` | `--no-requirements` |
| `--requirements-url <url>` | `--requirements <url>` |
