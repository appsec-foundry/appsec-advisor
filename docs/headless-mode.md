# Non-interactive Mode (Headless runs for CI/CD, scheduled scans, and AppSec ops)

Runs the plugin via Claude Code's headless mode (`claude -p`) with the same plugin, agents, and skills as interactive mode, but driven from a shell script instead of a chat session. The wrapper `scripts/run-headless.sh` handles authentication detection, permission-mode selection, duration/budget caps, and exit-code propagation so downstream CI steps can gate on the result.

The same wrapper covers three non-interactive scenarios: local full-assessments from a developer shell, AppSec-team batch runs across external repositories, and scheduled CI/CD pipelines. The decision matrix below maps goals to sections.

## Contents

- [Decision matrix — which use case?](#decision-matrix)
- [Minimal example (60-second CI snippet)](#minimal-example)
- [Prerequisites](#prerequisites)
- [Part A — Non-interactive local & ops runs](#part-a)
  - [A1. Scan your own repository](#a1-scan-your-own-repository)
  - [A2. AppSec team scans an external repository](#a2-appsec-team-scans-an-external-repository)
  - [A3. Cost-limited / time-capped assessments](#a3-cost-limited--time-capped-assessments)
  - [A4. Requirements compliance check (standalone)](#a4-requirements-compliance-check-standalone)
  - [A5. Full-featured assessment](#a5-full-featured-assessment)
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

## Decision matrix — which use case?

Each row links to the section covering that scenario.

| Goal | Who typically runs it | Section | Typical cost / time |
|---|---|---|---|
| Generate a threat model of the repo you are developing | Developer, locally | [A1](#a1-scan-your-own-repository) | ~$2 / 25 min (standard) |
| Assess a team's repo without touching it | AppSec engineer | [A2](#a2-appsec-team-scans-an-external-repository) | ~$2–5 / 25–40 min |
| Explore / cap spend before a full run | Anyone | [A3](#a3-cost-limited--time-capped-assessments) | <$1 (dry-run) |
| Verify that `[SEC-*]` requirements are implemented | Dev or AppSec | [A4](#a4-requirements-compliance-check-standalone) | ~$0.50–2 / 3–8 min |
| Deep-scan with Opus, SCA, and custom requirements | AppSec deep dive | [A5](#a5-full-featured-assessment) | ~$10–20 / 40+ min |
| **Scheduled CI scan** (weekly/daily) | CI pipeline | [B3](#b3-github-actions) / [B4](#b4-gitlab-ci) / [B5](#b5-jenkins) | ~$2–5 / 25 min |
| **Gate a PR** on new Critical/High findings | CI pipeline | [B6](#b6-pr-gating) | ~$0.30–1.50 / 2–8 min |

<a id="minimal-example"></a>

## Minimal example (60-second CI snippet)

The smallest useful CI invocation. Incremental scan, hard duration cap, budget cap, and SARIF export for GitHub Code Scanning:

```bash
./scripts/run-headless.sh \
  --incremental \
  --max-duration 1800 \
  --max-budget 5 \
  --sarif
```

- `--incremental` — re-analyse only components affected by recent changes (carries forward prior STRIDE findings).
- `--max-duration 1800` — abort after 30 min. Needed in CI: a full-scan fallback can otherwise outlive the runner budget.
- `--max-budget 5` — stop when estimated API spend hits $5. Stops gracefully; resumable via `--resume`.
- `--sarif` — emit `threat-model.sarif.json` for upload to GitHub/GitLab code scanning or any SARIF-aware tool.

## Prerequisites

1. **Claude Code CLI** installed and on your `PATH` ([installation guide](https://claude.ai/download)).
2. **Authentication** — one of:
   - **API key** (per-token billing): `export ANTHROPIC_API_KEY="sk-ant-..."` — recommended for CI. Use `--max-budget` to cap spend.
   - **Subscription** (Claude Pro / Team / Enterprise): run `claude auth login` first. Works locally; **does not work in a non-TTY CI runner** — see [Authentication in non-interactive mode](#authentication).
3. The plugin repository cloned locally (or installed into `~/.claude/plugins/`).

The script auto-detects billing mode from `ANTHROPIC_API_KEY`. When API billing is active without `--max-budget`, a warning is printed.

<a id="part-a"></a>

## Part A — Non-interactive local & ops runs

All five A-cases use `run-headless.sh` without CI-specific flags. They are meant for developer terminals, AppSec laptops, or manually triggered ad-hoc runs.

<a id="a1-scan-your-own-repository"></a>

### A1. Scan your own repository

Developer workflow: run the full assessment from your repo root. Output lands in `docs/security/` by default:

```bash
# Minimal — full threat model of the current repo
cd /path/to/my-project
/path/to/appsec-advisor/scripts/run-headless.sh

# With YAML and SARIF exports for downstream tooling
/path/to/appsec-advisor/scripts/run-headless.sh --sarif

# Dry-run first to preview scope and estimated complexity
/path/to/appsec-advisor/scripts/run-headless.sh --dry-run

# Re-analyse only affected components after code changes
/path/to/appsec-advisor/scripts/run-headless.sh --incremental

# Full assessment with SCA dependency scan
/path/to/appsec-advisor/scripts/run-headless.sh --sarif --with-sca
```

Result: `docs/security/threat-model.md` (+ `.yaml`, `.sarif.json` when requested). YAML is always emitted unless `--no-yaml` is passed, because subsequent incremental runs need it as baseline.

<a id="a2-appsec-team-scans-an-external-repository"></a>

### A2. AppSec team scans an external repository

Analyse a team's repository without modifying it; write all output to a central AppSec location:

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

When `--output` points outside the target repo, nothing is written into the team's repository — useful for scanning repos where you have read access only.

<a id="a3-cost-limited--time-capped-assessments"></a>

### A3. Cost-limited / time-capped assessments

`--max-budget` caps API spend; `--max-duration` caps wall-clock time. Either flag alone is a graceful stop — combine them for defence-in-depth in untrusted / long-running environments.

```bash
# Free preview — dry-run uses minimal tokens, no model dispatch
./scripts/run-headless.sh --repo /repos/large-monorepo --dry-run

# Cap at $3 — enough for a small-to-medium repo
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
  --sarif --requirements --with-sca \
  --max-budget 10 \
  --max-duration 2400
```

When the budget or duration limit fires, Claude Code stops gracefully and writes a checkpoint. Use `--resume` to continue:

```bash
# Budget ran out at Phase 7 — resume from the last checkpoint
./scripts/run-headless.sh \
  --repo /repos/large-monorepo \
  --max-budget 5 \
  --resume
```

<a id="a4-requirements-compliance-check-standalone"></a>

### A4. Requirements compliance check (standalone)

Run the `check-appsec-requirements` skill to verify security requirements against a codebase — without running a full STRIDE analysis:

```bash
# All requirements
./scripts/run-headless.sh --check-requirements

# Filter to a single category
./scripts/run-headless.sh --check-requirements --category SEC-AUTH

# Save the report (Markdown + JSON)
./scripts/run-headless.sh --check-requirements --save-report

# External repo
./scripts/run-headless.sh --check-requirements --repo /repos/team-frontend --save-report

# Combined: threat model with requirements AND a standalone requirements report
./scripts/run-headless.sh --repo /repos/team-api --requirements --sarif
./scripts/run-headless.sh --check-requirements --repo /repos/team-api --save-report
```

Output: console report with pass/fail per requirement, VS Code deep links to evidence, remediation roadmap. With `--save-report` also writes `docs/security/appsec-requirements-report.md` and `.json`.

<a id="a5-full-featured-assessment"></a>

### A5. Full-featured assessment

Thorough deep-dive with Opus reasoning, SCA, custom requirements, verbose streaming:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-payment-api \
  --output /appsec-reports/team-payment-api/2026-04-09 \
  --assessment-depth thorough \
  --model opus \
  --stride-model opus \
  --sarif \
  --requirements https://security.example.com/appsec-requirements.yaml \
  --with-sca \
  --max-budget 15 \
  --verbose
```

At `thorough` depth with Opus on the reasoning-heavy agents (STRIDE analyser, triage validator, threat merger), cost rises roughly 5× versus Sonnet, duration ~1.5×. Cost/duration scales non-linearly with code size — run `--dry-run` first on anything above ~100 KLOC to size the budget.

Verbose mode streams two log files to stderr in real time:
- `$OUTPUT_DIR/.agent-run.log` — phase progress, sub-agent lifecycle, step-by-step detail
- `$OUTPUT_DIR/.hook-events.log` — hook events, token usage, per-agent cost

<a id="part-b"></a>

## Part B — CI/CD pipelines

Everything in Part B assumes non-TTY execution with an `ANTHROPIC_API_KEY` secret. For interactive / local runs, use Part A.

<a id="b1-cadence"></a>

### B1. Cadence — when to run in CI

A full threat model takes 15–40 minutes and incurs non-trivial API cost. The trigger should match what the pipeline is supposed to verify — a PR gate proves a different thing than a weekly baseline scan.

| Trigger | Recommendation | Typical mode |
|---|---|---|
| Every push on main branch | Not recommended | — |
| Every pull request | Only with `--pr-mode --incremental --fail-on high` (narrow delta) | ~$0.30–1.50 per PR |
| PR labelled `security-review` | Recommended — manual trigger with full scan | `--full` |
| Nightly / weekly schedule | Recommended — rolling full scan | `--full --sarif` |
| Release pipeline | Recommended — blocking on Critical | `--full --fail-on critical` |
| `workflow_dispatch` (manual) | Recommended — when reviewer requests | any mode |

`--incremental` with no changes detected returns in ~60 s and ~$0.05 — fine for a gate but the result is "no new findings", not "repo is clean". Keep a periodic full scan alongside.

<a id="b2-cost--duration-planning"></a>

### B2. Cost & duration planning

Rough ranges for a ~50 KLOC Node or Java repo, Sonnet default, YAML baseline present:

| Depth | Models | Typical duration | Typical cost | Good for |
|---|---|---|---|---|
| `quick` | Sonnet | 10–15 min | ~$1 | PR gates, smoke tests, small repos |
| `standard` (default) | Sonnet | 20–30 min | ~$2–4 | Scheduled full scans |
| `standard` | Opus (reasoning) | 30–40 min | ~$8–12 | Higher signal on merge / triage |
| `thorough` | Sonnet | 35–50 min | ~$5–8 | Release gates |
| `thorough` | Opus | 45–70 min | ~$15–25 | Deep audit, compliance readouts |

Incremental runs are typically 1/3 to 1/2 of the full-scan cost when <30% of components changed. Always pair CI runs with `--max-budget` set to ~1.5× the expected cost so a surprise full-scan fallback does not blow up the API bill.

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

      # Restore prior run artefacts so incremental has a baseline
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
            --check-requirements \
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

`--pr-mode` produces a focused *delta* report for a merge request: implies `--incremental`, uses `--base <ref>` (target branch) to compute the diff, and emits only threats introduced in the PR.

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

Default PR gates to `high` rather than `critical`: Critical findings should block releases, High findings flag PRs for reviewer attention without blocking routine work. Adjust based on your false-positive rate.

<a id="b7-ci-cache"></a>

### B7. CI cache: `--restore-from` for incremental runs

Incremental runs need a prior `threat-model.yaml` as baseline. In CI the workspace is clean on every run, so pull the baseline from CI cache or from a previous pipeline's artifacts:

```bash
# Pull a prior artefact into the expected location before running
./scripts/run-headless.sh \
  --restore-from ./prior-run/docs/security/ \
  --incremental \
  --sarif \
  --max-budget 3
```

Alternatively, use the native cache step your CI provider offers (examples in [B3](#b3-github-actions) / [B4](#b4-gitlab-ci)). Both approaches are equivalent — pick whichever your CI system makes idiomatic.

<a id="authentication"></a>

## Authentication in non-interactive mode

Two billing modes are supported. They differ significantly in how they behave in CI.

| Mode | How to activate | Works in TTY terminal | Works in CI runner (non-TTY) |
|---|---|---|---|
| API key (per-token) | `export ANTHROPIC_API_KEY=sk-ant-...` | Yes | **Yes** — recommended for CI |
| Subscription (Pro / Team / Enterprise) | `claude auth login` — stores refresh token in `~/.claude/` | Yes | **No** — `auth login` needs a browser |

For CI use, always use an API key injected as a CI secret (`ANTHROPIC_API_KEY`). Subscription auth requires an interactive browser step that is incompatible with headless CI runners.

If you must run subscription-based auth from a pipeline (dedicated self-hosted runner you control), perform `claude auth login` once on that runner and copy `~/.claude/` into the CI user's home; the stored refresh token will then work non-interactively until it expires. This is a workaround, not a supported path — API key auth is the right CI answer.

<a id="security-and-permissions"></a>

## Security and permissions

The headless script runs with `--permission-mode bypassPermissions` and a fixed tool allowlist: `Read`, `Write`, `Glob`, `Grep`, `Bash`, `Agent`. No other tools are available during headless execution — stricter than interactive mode, where users can approve additional tools on demand.

**What the agent sees and sends.** Every file the recon scanner or STRIDE analysers read is sent to the Anthropic API as part of the prompt. The plugin does no secret scrubbing beyond what `SECURITY.md` → [Data Sent to Anthropic API](../SECURITY.md#data-sent-to-anthropic-api) documents. Run on a clean checkout or exclude sensitive files via `.gitignore` / recon filters before pointing the script at a repository with committed secrets.

**Write scope.** Writes are limited to `$OUTPUT_DIR` (default `<repo>/docs/security/`). The `--repo` target is read-only unless `$OUTPUT_DIR` lies inside it, which is the normal dev-team layout. To analyse without any writes into the target repo, always pass `--output` to a path outside it.

**Credentials.** `ANTHROPIC_API_KEY` is read from the environment and forwarded to the Claude Code CLI — it never lands in any log or output file. `HARVEST_AUTH_TOKEN` is only consumed by the harvester script, not by the skill. No other authentication material is expected.

**Logging.** `.agent-run.log` and `.hook-events.log` record agent lifecycle events, file paths touched, token counts, and cost estimates. Prompt and response bodies are **not** written to either log. Both rotate at 5 MB. If the logs themselves are sensitive in your threat model (e.g. file paths leak product structure), restrict access to `$OUTPUT_DIR`.

**Concurrency.** `.appsec-lock` prevents overlapping runs against the same `$OUTPUT_DIR`. Stale locks older than 1 h are auto-overwritten — in CI, this means a failed previous run does not block the next scheduled build indefinitely.

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
| `appsec-requirements-report.md` / `.json` | `--check-requirements --save-report` | Requirements compliance report |
| `.agent-run.log` | Always | Agent lifecycle, phase progress, step detail |
| `.hook-events.log` | Always | Hook events, token usage, cost per agent |
| `.threat-modeling-context.md` | Always | Combined context from all sources |
| `.recon-summary.md` | Always | Repository structure and security findings |
| `.dep-scan.json` | `--with-sca` | SCA dependency scan results |
| `.stride-*.json` | Always | Per-component STRIDE threat analysis |
| `.threats-merged.json` | Always | Canonical merged threat list (annotated with triage flags) |
| `.triage-flags.json` | Always | Triage validation flags (rating consistency, plausibility) |
| `.appsec-cache/baseline.json` | Always | Incremental-mode carry-forward cache |
| `.appsec-lock` | During run | Prevents concurrent assessments (auto-deleted) |

<a id="flag-reference"></a>

## Flag reference

Not every `create-threat-model` flag is accepted by the wrapper. This table lists everything `run-headless.sh` exposes today.

### Scope & targeting

| Flag | Purpose |
|---|---|
| `--repo <path>` | Repository to analyse (default: current working directory) |
| `--output <path>` | Output directory (default: `<repo>/docs/security`) |
| `--incremental` | Force delta analysis based on git diff |
| `--full` | Force full scan even when prior output exists |
| `--base <ref>` | Git ref to diff `HEAD` against (default: commit SHA recorded in prior `threat-model.yaml`) |
| `--pr-mode` | Focused delta report for MR/PR (implies `--incremental`) |
| `--dry-run` | Preview scope without running the full pipeline |
| `--resume` | Continue from last checkpoint |
| `--restore-from <path>` | Hydrate `$OUTPUT_DIR` from a prior-run artefact before running |

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
| `--assessment-depth quick\|standard\|thorough` | Depth control (3/5/8 STRIDE components) |
| `--requirements [<url>]` | Enable Phase 8b requirements compliance check |
| `--no-requirements` | Skip requirements even when enabled in config |
| `--with-sca` | Run SCA dependency scan (`npm audit`, `pip-audit`, …) |

### Models

| Flag | Purpose |
|---|---|
| `--model <model>` | Override the default Claude model (default: sonnet) |
| `--stride-model <model>` | Override model for STRIDE analysers (e.g. `opus`) |

### Gates & caps

| Flag | Purpose |
|---|---|
| `--max-duration <sec>` | Abort the run if it exceeds the given wall-clock duration |
| `--max-budget <usd>` | Stop when estimated cost exceeds this amount |
| `--fail-on critical\|high\|medium` | Exit code 20 when delta contains threats at or above `<level>` |
| `--no-qa` | Skip Stage-3 QA reviewer (faster CI runs; accept slightly weaker output contract) |

### Housekeeping

| Flag | Purpose |
|---|---|
| `--clean-cache` | Delete cache & transient files in `$OUTPUT_DIR`; keeps the threat model. Exits without running. |
| `--clean-all` | Delete everything in `$OUTPUT_DIR` (interactive confirm unless `--force` / `CI=true`). Exits without running. |
| `--force` | Skip the interactive confirmation for `--clean-all` |

### Skill selection

| Flag | Purpose |
|---|---|
| `--check-requirements` | Run `check-appsec-requirements` instead of the threat model |
| `--category <filter>` | Category filter for requirements check (e.g. `SEC-AUTH`) |
| `--save-report` | Save requirements report (Markdown + JSON) |

<a id="troubleshooting"></a>

## Troubleshooting

**"No credentials found" / `claude auth login` prompt in CI.**
The pipeline is trying to use subscription auth. Set `ANTHROPIC_API_KEY` as a CI secret and pass it through as env (`env: ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}` in GitHub Actions). See [Authentication in non-interactive mode](#authentication).

**Incremental scan keeps doing a full scan.**
Incremental needs `threat-model.yaml` from a prior run as baseline. In CI, the workspace is clean every run — restore the prior `docs/security/` via CI cache or `--restore-from`. See [B7](#b7-ci-cache). Also check that you are not passing `--no-yaml` earlier in the pipeline — that breaks the baseline.

**`.appsec-lock` exists and blocks the run.**
A previous run crashed. Locks older than 1 h are auto-overwritten. For faster recovery in a stuck pipeline, delete `$OUTPUT_DIR/.appsec-lock` before invoking the script — or pre-run `scripts/run-headless.sh --clean-cache`, which also removes the lock.

**Script exits with code 2 "budget exhausted" in the middle of a run.**
Expected behaviour at the cap. Re-run with `--resume` on the same `$OUTPUT_DIR` — or raise `--max-budget` if the cap was too tight. Dry-run first (`--dry-run`) to size the budget before expensive runs.

**GitHub Actions: SARIF upload silently skipped.**
The job needs `permissions: security-events: write` and the workflow needs `contents: read` or `write`. Without those, the upload step is a no-op.

**Relative `--output` path resolves to the plugin directory, not the repo.**
Pass absolute paths for `--output` when working from a different directory, or run from the repo root. The wrapper resolves relative paths against the current working directory at invocation time, not against `--repo`.

**Run starts, but no progress for >5 minutes.**
Enable `--verbose` to tail `.agent-run.log` on stderr. Phase 2 (recon scanner) is typically the longest silent phase on large repos — if it is stuck >10 min, abort with Ctrl-C and rerun with `--dry-run` to check the recon scope.

**"timeout: command not found" warning when `--max-duration` is set.**
The wrapper uses the GNU `timeout` utility when `--max-duration` is active. On minimal CI images (e.g. Alpine without `coreutils`), install it (`apk add coreutils`) or drop `--max-duration` in favour of the Anthropic-side `--max-budget` cap.

**PR gate fires on threats that already existed in main.**
Use `--pr-mode` instead of plain `--incremental`; `--pr-mode` scopes the delta against `--base` and filters out pre-existing findings.

<a id="deprecated-flags"></a>

## Deprecated flags

Still accepted for backward compatibility; will print a deprecation warning:

| Deprecated | Use instead |
|---|---|
| `--with-requirements` | `--requirements` |
| `--ignore-requirements` | `--no-requirements` |
| `--requirements-url <url>` | `--requirements <url>` |
