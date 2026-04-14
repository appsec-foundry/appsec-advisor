# Headless Mode (Non-Interactive / CI/CD)

> Back to [README](../README.md) | [Flag Reference](flags-reference.md)

The plugin can run **non-interactively** via Claude Code's headless mode (`claude -p`). This requires zero code changes — the same plugin, agents, and skills execute exactly as they do in interactive mode, but driven from a shell script instead of a chat session.

A ready-to-use wrapper script is included at `scripts/run-headless.sh`.

## Contents

- [Prerequisites](#prerequisites)
- [Use Cases](#use-cases)
  - [1. Scan your own repository](#use-case-1-scan-your-own-repository)
  - [2. Scan an external repository](#use-case-2-scan-an-external-repository)
  - [3. Cost-limited assessments](#use-case-3-cost-limited-assessments)
  - [4. Requirements compliance check](#use-case-4-requirements-compliance-check)
  - [5. Full-featured assessment](#use-case-5-full-featured-assessment)
  - [6. CI/CD pipeline integration](#use-case-6-cicd-pipeline-integration)
- [Security and permissions](#security-and-permissions)
- [Exit codes](#exit-codes)
- [Output files](#output-files)
- [Deprecated flags](#deprecated-flags)

## Prerequisites

1. **Claude Code CLI** installed and on your `PATH` ([installation guide](https://claude.ai/download))
2. **Authentication** — one of:
   - **API key** (per-token billing): `export ANTHROPIC_API_KEY="sk-ant-..."` — use `--max-budget` to cap spend
   - **Subscription** (included with Claude Pro/Team/Enterprise): run `claude auth login` first — no API key needed
3. The plugin repository cloned locally

The script auto-detects billing mode from the presence of `ANTHROPIC_API_KEY`. When using API billing without `--max-budget`, a warning is printed.

## Use Cases

### Use Case 1: Scan your own repository

You are a developer working inside your project. Run the full assessment from your repo root — output goes to `docs/security/` by default:

```bash
# Minimal — full threat model
cd /path/to/my-project
/path/to/appsec-plugin/scripts/run-headless.sh

# With YAML and SARIF exports for downstream tooling
/path/to/appsec-plugin/scripts/run-headless.sh --yaml --sarif

# Dry-run first to preview scope and estimated complexity
/path/to/appsec-plugin/scripts/run-headless.sh --dry-run

# After code changes — only re-analyze affected components
/path/to/appsec-plugin/scripts/run-headless.sh --incremental

# Full assessment with SCA dependency scan (npm audit, pip-audit, etc.)
/path/to/appsec-plugin/scripts/run-headless.sh --yaml --sarif --with-sca
```

**Result:** `docs/security/threat-model.md` (+ `.yaml`, `.sarif.json` if requested) in your project.

### Use Case 2: Scan an external repository

You are on the AppSec team. Analyze a team's repository without modifying it, writing all output to a central location:

```bash
# Analyze external repo — output goes to docs/security/ inside that repo
./scripts/run-headless.sh --repo /repos/team-frontend

# Analyze external repo — write output to a central AppSec directory
./scripts/run-headless.sh \
  --repo /repos/team-frontend \
  --output /appsec-reports/team-frontend

# Dated output directory for audit trail
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api/2026-04-08 \
  --yaml --sarif

# Incremental review after a team pushed changes
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --incremental

# Dry-run to preview what would be analyzed before committing budget
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --dry-run
```

**Result:** All output files land in the `--output` directory. The target repository remains untouched.

### Use Case 3: Cost-limited assessments

Use `--max-budget` to cap API spend. Combined with `--dry-run`, this allows safe exploration before committing to a full run:

```bash
# Preview scope for free (dry-run uses minimal tokens)
./scripts/run-headless.sh --repo /repos/large-monorepo --dry-run

# Cap at $3 — enough for a small-to-medium repo
./scripts/run-headless.sh --repo /repos/small-service --max-budget 3

# Cap at $8 — suitable for larger repos with full exports
./scripts/run-headless.sh \
  --repo /repos/large-monorepo \
  --yaml --sarif --requirements \
  --max-budget 8

# Include requirements compliance + SCA within budget
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --yaml --sarif --requirements --with-sca \
  --max-budget 10
```

When the budget limit is reached, Claude Code stops gracefully. Use `--resume` on a subsequent run to continue from the last checkpoint:

```bash
# Budget ran out at Phase 7 — resume from there
./scripts/run-headless.sh \
  --repo /repos/large-monorepo \
  --max-budget 5 \
  --resume
```

### Use Case 4: Requirements compliance check

Run the standalone `check-appsec-requirements` skill to verify security requirements against a codebase — without running a full threat model:

```bash
# Check all requirements
./scripts/run-headless.sh --check-requirements

# Filter to a specific category (e.g. authentication)
./scripts/run-headless.sh --check-requirements --category SEC-AUTH

# Save the report as Markdown + JSON
./scripts/run-headless.sh --check-requirements --save-report

# Filter and save
./scripts/run-headless.sh --check-requirements --category SEC-AUTH --save-report

# Check requirements for an external repo
./scripts/run-headless.sh --check-requirements --repo /repos/team-frontend

# Combine: threat model with requirements + standalone requirements check
./scripts/run-headless.sh --repo /repos/team-api --requirements --yaml
./scripts/run-headless.sh --check-requirements --repo /repos/team-api --save-report
```

**Output:** Console report with pass/fail per requirement, VS Code deep links to evidence, and a remediation roadmap. With `--save-report`, also writes `docs/security/appsec-requirements-report.md` and `.json`.

### Use Case 5: Full-featured assessment

A thorough assessment of an external repository with all analysis features enabled, custom requirements, Opus-powered STRIDE, and verbose real-time output:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-payment-api \
  --output /appsec-reports/team-payment-api/2026-04-09 \
  --assessment-depth thorough \
  --stride-model opus \
  --yaml --sarif \
  --requirements https://security.example.com/appsec-requirements.yaml \
  --with-sca \
  --max-budget 15 \
  --verbose
```

This command:
- Analyzes `/repos/team-payment-api` without modifying it
- Writes all output to a dated directory under `/appsec-reports/`
- Uses `thorough` depth (up to 8 STRIDE components, extended diagrams)
- Runs STRIDE analyzers on Opus for higher-quality threat analysis (~5x cost vs Sonnet)
- Produces all three output formats (Markdown, YAML, SARIF)
- Loads security requirements from a custom URL for Phase 8b compliance checking
- Includes SCA dependency vulnerability scanning (npm audit, pip-audit, etc.)
- Caps total API spend at $15
- Streams real-time progress to stderr (phase transitions, control ratings, STRIDE dispatch)

**Verbose output** streams two log files to stderr in real-time:
- `$OUTPUT_DIR/.agent-run.log` — phase progress, sub-agent lifecycle, step-by-step detail
- `$OUTPUT_DIR/.hook-events.log` — hook events, token usage, cost tracking per agent

### Use Case 6: CI/CD pipeline integration

Use the headless script in any CI system. Example for **GitHub Actions**:

```yaml
# .github/workflows/threat-model.yml
name: Threat Model Assessment
on:
  pull_request:
    types: [opened, synchronize]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

jobs:
  threat-model:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Install Claude Code
        run: npm install -g @anthropic-ai/claude-code

      - name: Clone AppSec Plugin
        run: git clone https://github.com/your-org/appsec-plugin.git /tmp/appsec-plugin

      - name: Run Threat Model (incremental on PRs)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          /tmp/appsec-plugin/scripts/run-headless.sh \
            --sarif \
            --incremental \
            --max-budget 5

      - name: Upload SARIF to GitHub Code Scanning
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

For **requirements compliance** in CI:

```yaml
  requirements-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Claude Code
        run: npm install -g @anthropic-ai/claude-code
      - name: Clone AppSec Plugin
        run: git clone https://github.com/your-org/appsec-plugin.git /tmp/appsec-plugin
      - name: Check Requirements
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          /tmp/appsec-plugin/scripts/run-headless.sh \
            --check-requirements \
            --save-report \
            --max-budget 3
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: requirements-report
          path: docs/security/appsec-requirements-report.*
```

## Security and permissions

The headless script runs with `--permission-mode bypassPermissions` and a fixed tool allowlist: `Read`, `Write`, `Glob`, `Grep`, `Bash`, `Agent`. No other tools are available to the plugin during headless execution. This is stricter than interactive mode where users can approve additional tools.

## Exit codes

The script propagates the exit code from the `claude` CLI:
- **0** — assessment completed successfully
- **1** — assessment failed (agent error, lock conflict, missing prerequisites)
- **2** — budget exhausted before completion (use `--resume` to continue)

In CI/CD pipelines, check the exit code to determine whether to proceed with SARIF upload or artifact collection.

## Output files

All files are written to `$OUTPUT_DIR` (default: `<repo>/docs/security/`):

| File | When created | Purpose |
|------|-------------|---------|
| `threat-model.md` | Always | Human-readable threat model report |
| `threat-model.yaml` | `--yaml` | Machine-readable YAML export |
| `threat-model.sarif.json` | `--sarif` | SARIF v2.1.0 for CI/CD integration |
| `.agent-run.log` | Always | Agent lifecycle, phase progress, step detail |
| `.hook-events.log` | Always | Hook events, token usage, cost per agent |
| `.threat-modeling-context.md` | Always | Combined context from all sources |
| `.recon-summary.md` | Always | Repository structure and security findings |
| `.dep-scan.json` | `--with-sca` | SCA dependency scan results |
| `.stride-*.json` | Always | Per-component STRIDE threat analysis |
| `.threats-merged.json` | Always | Canonical merged threat list (annotated with triage flags) |
| `.triage-flags.json` | Always | Triage validation flags (rating consistency, plausibility) |
| `.appsec-checkpoint` | Always | Phase progress (for `--resume`) |
| `.appsec-lock` | During run | Prevents concurrent assessments (auto-deleted) |

## Deprecated flags

These flags still work but print a deprecation warning:

| Deprecated | Use instead |
|-----------|-------------|
| `--with-requirements` | `--requirements` |
| `--ignore-requirements` | `--no-requirements` |
| `--requirements-url <url>` | `--requirements <url>` |
