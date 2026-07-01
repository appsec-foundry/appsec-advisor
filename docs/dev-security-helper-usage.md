# Dev Security Helper

`appsec-advisor` includes prompt-time guidance, an interactive change review, and a CI review command.

All tools use the same active standard: a configured company requirements catalog, or the bundled best-practices baseline when no catalog is configured.

## Contents

- [Quick start](#quick-start)
- [Tool overview](#tool-overview)
- [Setup and prerequisites](#setup-and-prerequisites)
- [Security Coach hook](#security-coach-hook)
- [appsec-reviewer agent](#appsec-reviewer-agent)
- [verify-requirements skill](#verify-requirements-skill)
- [appsec-reviewer-cli](#appsec-reviewer-cli)
- [Requirements source](#requirements-source)
- [Diff behavior](#diff-behavior)
- [Outputs and gates](#outputs-and-gates)
- [CI security notes](#ci-security-notes)
- [Troubleshooting](#troubleshooting)
- [Flag reference](#flag-reference)

## Quick start

Use the hook while writing code:

```bash
APPSEC_COACH=1 claude --plugin-dir /path/to/appsec-advisor
```

Review the change you just made from a Claude Code session:

```bash
/appsec-advisor:verify-requirements
```

Review staged changes before commit:

```bash
/appsec-advisor:verify-requirements --staged
```

Write an advisory CI report:

```bash
export CLAUDE_PLUGIN_ROOT="/path/to/appsec-advisor"
export PATH="$CLAUDE_PLUGIN_ROOT/scripts:$PATH"
appsec-reviewer-cli review --diff origin/main --output security-review.md
```

Make CI fail on blocking findings:

```bash
appsec-reviewer-cli review --diff origin/main --output security-review.md --fail-on must
```

## Tool overview

| Tool | Type | What it does | When to use it |
|------|------|--------------|----------------|
| [Security Coach hook](#security-coach-hook) | Hook | Adds relevant security guidance to Claude's context while you write. It advises before code exists; it does not review finished code or block prompts. | You want automatic reminders as you write security-sensitive code. |
| [appsec-reviewer](#appsec-reviewer-agent) | Agent | Reads a change, determines which security expectations apply, and grades the post-change code with evidence and a suggested fix. It produces findings only. | You want to embed the reviewer into your own Claude Code or Agent SDK workflow. |
| [verify-requirements](#verify-requirements-skill) | Skill | Interactive wrapper for Claude Code sessions. It resolves the requirements source, builds the diff, dispatches `appsec-reviewer`, and can enforce the result with `--gate`. | You want to review the change you just made in your session. |
| [appsec-reviewer-cli](#appsec-reviewer-cli) | CLI | CI wrapper around the same review. It runs headlessly, writes a Markdown report, and can fail the build with `--fail-on`. | You want the review to run automatically in CI on every change. |

The Security Coach acts before code is written. The skill and CLI use `appsec-reviewer` to inspect a completed change.

## Setup and prerequisites

Interactive use needs Claude Code with the plugin loaded:

```bash
claude --plugin-dir /path/to/appsec-advisor
```

CLI use needs:

- `appsec-reviewer-cli` on `PATH`, usually by adding the plugin's `scripts/` directory.
- `CLAUDE_PLUGIN_ROOT` pointing at the plugin root when the wrapper cannot resolve it from its own path.
- Claude Code CLI on `PATH`.
- `python3` and `git` on `PATH`.
- `ANTHROPIC_API_KEY` or Claude Code subscription authentication.
- A fetched base ref when using `--diff` in CI, such as `origin/main`.

Minimal shell setup:

```bash
export CLAUDE_PLUGIN_ROOT="/path/to/appsec-advisor"
export PATH="$CLAUDE_PLUGIN_ROOT/scripts:$PATH"
```

Set `CLAUDE_PLUGIN_ROOT` to the plugin's location in the CI runner.

## Security Coach hook

The Security Coach checks prompts for topics such as authentication, injection, cryptography, secrets, IaC, and LLM security. On a match, it adds relevant guidance and requirements before Claude answers.

Enable per session:

```bash
APPSEC_COACH=1 claude --plugin-dir /path/to/appsec-advisor
```

Enable for all team members via org profile:

```yaml
# org-profile.yaml
security_coach:
  enabled_by_default: true
```

The org profile enables the hook for the team; `APPSEC_COACH=1` enables it for one session.

Example prompt:

```text
implement the OAuth refresh-token endpoint
```

Example injected context:

```text
[auth] short-lived tokens with rotation on refresh; validate
issuer/audience/signature/expiry on every JWT check; MFA for admin paths.

Applicable requirements:
  - BP-AUTH-SESSION-COOKIE (MUST): Issue session cookies with HttpOnly, Secure...
```

Operational notes:

- The hook does not call the reviewer agent.
- The hook does not block prompts.
- Matching and telemetry are documented in [security-coach-skill.md](security-coach-skill.md).

## appsec-reviewer agent

`appsec-reviewer` is the core reviewer. It reads a diff, determines which requirements or best-practice rules are in scope, and grades the post-change code.

Each finding includes:

- status: `PASS`, `PARTIAL`, `FAIL`, `UNVERIFIABLE`, or `NOT_APPLICABLE`
- rule or requirement ID
- `file:line` evidence where available
- code-aware fix
- effort estimate

Direct use:

```text
Use the appsec-reviewer agent to review my staged changes.
```

Output (in its configured output directory):

```text
<output-dir>/.requirements-verification.json
```

The agent writes findings. The skill and CLI apply the gate when requested.

## verify-requirements skill

The skill is the interactive entry point for developers using Claude Code.

Run:

```bash
/appsec-advisor:verify-requirements
```

By default, the skill:

- resolves the active requirements source
- builds a three-dot diff against the upstream default branch
- dispatches `appsec-reviewer`
- writes `docs/security/.requirements-verification.json`
- exits `0` unless `--gate` is set and the gate fails

Common runs:

```bash
# Review staged changes.
/appsec-advisor:verify-requirements --staged

# Compare against a specific base ref.
/appsec-advisor:verify-requirements --base origin/main

# Enforce locally or in a scripted Claude Code run.
/appsec-advisor:verify-requirements --gate

# Enforce and also block PARTIAL findings.
/appsec-advisor:verify-requirements --gate --gate-on partial
```

Saved reports:

```bash
/appsec-advisor:verify-requirements --save
```

`--save` writes:

- `docs/security/appsec-requirements-change-report.md`
- `docs/security/appsec-requirements-change-report.json`

## appsec-reviewer-cli

The CLI runs the same review in CI and other automation.

Run:

```bash
appsec-reviewer-cli review --diff origin/main --output security-review.md
```

By default, the CLI:

- invokes `/appsec-advisor:verify-requirements` headlessly
- writes `docs/security/.requirements-verification.json`
- renders the requested Markdown report
- exits `0` unless `--fail-on` is set and the gate fails

Before using this in CI, read [CI security notes](#ci-security-notes). Pull-request code is untrusted input, and the wrapper bypasses interactive permission prompts.

GitLab CI:

```yaml
security_review:
  stage: test
  script:
    - export CLAUDE_PLUGIN_ROOT="$CI_PROJECT_DIR/appsec-advisor"
    - export PATH="$CLAUDE_PLUGIN_ROOT/scripts:$PATH"
    - git fetch origin main
    - appsec-reviewer-cli review --diff origin/main --output security-review.md
  artifacts:
    paths:
      - security-review.md
```

GitHub Actions:

```yaml
permissions:
  contents: read

jobs:
  security_review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit-sha>
        with:
          fetch-depth: 0
      - name: Security review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          CLAUDE_PLUGIN_ROOT: ${{ github.workspace }}/appsec-advisor
          BASE_REF: ${{ github.base_ref }}
        run: |
          export PATH="$CLAUDE_PLUGIN_ROOT/scripts:$PATH"
          git fetch origin "$BASE_REF"
          appsec-reviewer-cli review --diff "origin/$BASE_REF" --output security-review.md
      - uses: actions/upload-artifact@<commit-sha>
        with:
          name: security-review
          path: security-review.md
```

Report excerpt:

```markdown
# Security Review — change verification

| Field | Value |
|-------|-------|
| Base ref | `origin/main` |
| Checked against | built-in best-practices baseline |
| In-scope requirements | 2 of 6 candidates |
| Result | 🔴 1 fail · 🟡 1 partial · 🟢 0 pass · ⚪ 0 unverifiable |

## What to fix

### 🔴 FAIL · MUST · BP-INJ-SQL-PARAM

Raw request input reaches `sequelize.query()` at `src/routes/search.ts:23`.

**Fix:** Bind the term via replacements.
```

## Requirements source

The active requirements source is selected in this order:

1. Explicit `--requirements <src>` for the current run.
2. Configured organization requirements catalog.
3. Bundled best-practices baseline.

`<src>` can be an `http(s)://` URL or a local file path. A path without an `http(s)` scheme is read relative to the current working directory. If an explicit source cannot be loaded, the run exits with an error instead of silently falling back.

Examples:

```bash
/appsec-advisor:verify-requirements --requirements ./security/requirements.yaml
appsec-reviewer-cli review --diff origin/main --output security-review.md --requirements ./security/requirements.yaml
```

Minimal catalog:

```yaml
source: acme-appsec
categories:
  - id: ACME-AUTH
    title: Authentication
    requirements:
      - id: ACME-AUTH-01
        priority: MUST
        text: Passwords must be stored with Argon2id or bcrypt.
        url: https://wiki.acme.internal/appsec/auth
```

Requirement IDs are organization-defined. No fixed prefix is required. For org-wide defaults, use [org-profiles.md](org-profiles.md).

## Diff behavior

`verify-requirements --base <ref>` and `appsec-reviewer-cli review --diff <ref>` both review the changes on `HEAD` since the merge-base with `<ref>`:

```text
git diff <ref>...HEAD
```

Default interactive behavior uses the upstream default branch when it can be resolved, then common fallbacks such as `origin/main` or `origin/master`.

- `--staged` reviews only `git diff --cached`.
- `--staged` and `--base` are mutually exclusive.
- CI jobs must fetch the base ref before running the CLI.
- An empty diff is valid and exits `0` without dispatching the reviewer.

## Outputs and gates

Outputs:

- Hook: no review artifact; optional hook telemetry as described in [security-coach-skill.md](security-coach-skill.md).
- Agent: `.requirements-verification.json` in its configured output directory.
- Skill: `docs/security/.requirements-verification.json`; optional saved reports under `docs/security/`.
- CLI: requested Markdown report and `docs/security/.requirements-verification.json`.

Exit codes:

- `0`: review completed; advisory mode or no gate-violating finding.
- `1`: gate failed.
- `2`: usage, requirements-load, diff-build, or verdict error.

Gate behavior:

| Front-end | Advisory by default | Blocking flag | What blocks |
|-----------|---------------------|---------------|-------------|
| Skill | yes | `--gate` | in-scope `FAIL` findings at or above `--priority-floor` |
| Skill | yes | `--gate --gate-on partial` | in-scope `FAIL` or `PARTIAL` findings at or above `--priority-floor` |
| CLI | yes | `--fail-on must` | in-scope `FAIL` findings at or above `--priority-floor` |
| CLI | yes | `--fail-on partial` | in-scope `FAIL` or `PARTIAL` findings at or above `--priority-floor` |

`--priority-floor` defaults to `MUST`. Lower it to `SHOULD` or `MAY` only when the team intentionally wants lower-priority findings to block.

Pre-push example:

```bash
# .git/hooks/pre-push   (chmod +x)
#!/usr/bin/env bash
appsec-reviewer-cli review --diff origin/main --output /tmp/security-review.md --fail-on must
```

## CI security notes

Pull-request code is untrusted input. A CI job that runs the reviewer may expose an API key to attacker-controlled repository content.

The CLI invokes Claude Code in headless mode and bypasses interactive permission prompts so it can run unattended. Use it only where that is an acceptable trust boundary.

Use the CI reviewer with:

- private repositories
- trusted same-repository pull requests
- ephemeral runners
- dedicated, low-limit CI API keys

Do not use it with:

- public fork pull requests with secrets
- `pull_request_target` workflows that bypass secret withholding
- shared runners that retain sensitive state
- long-lived developer credentials in the CI environment

See [SECURITY.md](../SECURITY.md#known-issues--untrusted-repositories).

## Troubleshooting

- `appsec-reviewer-cli: CLAUDE_PLUGIN_ROOT could not be resolved`: set `CLAUDE_PLUGIN_ROOT` to the plugin root and add `$CLAUDE_PLUGIN_ROOT/scripts` to `PATH`.
- `Claude Code CLI not found`: install Claude Code and make sure `claude` is on `PATH`.
- `no verdict produced`: the headless Claude run did not complete or did not write `docs/security/.requirements-verification.json`. Re-run the equivalent `/appsec-advisor:verify-requirements --base <ref>` interactively to see the underlying error.
- `build-verify-diff: git diff failed`: fetch the base ref and verify that `git diff <ref>...HEAD` works locally.
- Explicit requirements source cannot be loaded: fix the URL/path or remove `--requirements`. Explicit sources fail closed; only the zero-config path falls back to the bundled best-practices baseline.
- `No changes to verify.`: the resolved diff is empty. Use `--staged` for staged-only checks or pass a different `--base` / `--diff` ref.

## Flag reference

### `/appsec-advisor:verify-requirements`

| Flag | Meaning |
|------|---------|
| `--base <ref>` | Review `git diff <ref>...HEAD`; default is the merge-base with the upstream default branch. |
| `--staged` | Review staged changes only (`git diff --cached`); mutually exclusive with `--base`. |
| `--gate` | Exit non-zero on a gating failure; default is advisory. |
| `--gate-on <fail\|partial>` | Select what counts as gating; default is `fail`. |
| `--priority-floor <MUST\|SHOULD\|MAY>` | Lowest priority allowed to gate; default is `MUST`. |
| `--requirements <src>` | Use an `http(s)://` URL or local file path; unreadable explicit sources abort. |
| `--org-profile <path>` | Use this org profile for source resolution. |
| `--preset <name>` | Use a preset from the active org profile. |
| `--no-org-profile` | Ignore packaged or environment-pointed org profiles. |
| `--md` | Also save `docs/security/appsec-requirements-change-report.md`. |
| `--json` | Also save `docs/security/appsec-requirements-change-report.json`. |
| `--save` | Save both Markdown and JSON reports under `docs/security/`. |

### `appsec-reviewer-cli review`

| Flag | Meaning |
|------|---------|
| `--diff <ref>` | Required base ref for `git diff <ref>...HEAD`. |
| `--output <file>` | Markdown report path; default is `security-review.md`. |
| `--requirements <src>` | Use an `http(s)://` URL or local file path; unreadable explicit sources abort. |
| `--fail-on <must\|partial>` | Make CI fail; omit for advisory mode. `must` gates FAIL findings, `partial` gates FAIL and PARTIAL findings. |
| `--priority-floor <MUST\|SHOULD\|MAY>` | Lowest priority allowed to gate; default is `MUST`. |
