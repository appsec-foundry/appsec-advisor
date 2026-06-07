# AppSec Reviewer Tools

This document explains the developer-facing security review tools in `appsec-advisor`: the steering hook, the reviewer agent, the interactive skill, and the CI CLI.

All tools use the same active standard: a configured company requirements catalog, or the bundled best-practices baseline when no catalog is configured.

## Contents

- [Tool overview](#tool-overview)
- [How the tools fit together](#how-the-tools-fit-together)
- [Security steering hook](#security-steering-hook)
- [appsec-reviewer agent](#appsec-reviewer-agent)
- [verify-requirements skill](#verify-requirements-skill)
- [appsec-reviewer-cli](#appsec-reviewer-cli)
- [Requirements source](#requirements-source)
- [Outputs and gates](#outputs-and-gates)
- [CI security notes](#ci-security-notes)
- [Flag reference](#flag-reference)

## Tool overview

| Tool | Type | What it does | When to use it |
|------|------|--------------|----------------|
| [Security steering hook](#security-steering-hook) | Hook | Adds the relevant security guidance to Claude's context while you write, so the requirement is in view before the code even exists. It only advises — it never reviews finished code or blocks anything. | You want automatic reminders as you write security-sensitive code. |
| [appsec-reviewer](#appsec-reviewer-agent) | Agent | The actual reviewer: it reads a change, works out which security expectations apply, and grades the result with evidence and a suggested fix. It reports findings but leaves the pass/fail decision to a separate step. | You want to embed the reviewer itself into your development process. |
| [verify-requirements](#verify-requirements-skill) | Skill | The interactive way to run the reviewer from a Claude Code session — it prepares the diff and the requirements for you, runs the agent, and can enforce the result with `--gate`. | You want to review the change you just made, in your session. |
| [appsec-reviewer-cli](#appsec-reviewer-cli) | CLI | The same review packaged as a command for pipelines: it runs headless, writes a Markdown report you can attach to a merge request, and can fail the build with `--fail-on`. | You want the review to run automatically in CI on every change. |

The agent does the actual reviewing; the skill and the CLI are just convenient front-ends around it. The hook is a separate thing — it guides you *before* you write code, rather than reviewing what you already wrote.

## How the tools fit together

```text
Security steering hook
  -> guidance before code is written

verify-requirements skill
  -> resolves requirements and diff
  -> dispatches appsec-reviewer
  -> writes docs/security/.requirements-verification.json
  -> optional --gate

appsec-reviewer-cli
  -> calls verify-requirements headlessly
  -> renders a Markdown report
  -> optional --fail-on gate

appsec-reviewer agent
  -> core reviewer used by the skill and CLI
```

The hook is proactive guidance. The agent, skill, and CLI are review paths for code that already changed.

## Security steering hook

The hook runs on `UserPromptSubmit`. It checks the user's prompt for security-relevant topics such as authentication, injection, cryptography, secrets, IaC, and LLM security. When a topic matches, it prepends the matching guidance and requirements before Claude answers.

Enable per session:

```bash
APPSEC_COACH=1 claude
```

Enable in plugin config:

```jsonc
// config.json
{ "security_coach": { "enabled": true } }
```

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

Output:

```text
.requirements-verification.json
```

The agent only writes findings. Gate decisions belong to `scripts/requirements_gate.py`; the skill and CLI call that script when gate mode is enabled.

Console finding shape:

```text
  - [FAIL] MUST  BP-INJ-SQL-PARAM  Parameterized SQL Queries
  Finding : raw request input reaches sequelize.query() in src/routes/search.ts:23
  Fix     : bind the term: sequelize.query(sql, { replacements: { term } })
  Effort  : M
```

## verify-requirements skill

The skill is the interactive entry point for developers using Claude Code.

Run:

```bash
/appsec-advisor:verify-requirements
```

Default behavior:

- resolves the active requirements source
- builds a diff against the merge-base with upstream
- dispatches `appsec-reviewer`
- writes `docs/security/.requirements-verification.json`
- exits `0` unless `--gate` is set and the deterministic gate fails

Common runs:

```bash
# Review staged changes.
/appsec-advisor:verify-requirements --staged

# Compare against a specific base ref.
/appsec-advisor:verify-requirements --base origin/main

# Enforce locally or in a scripted Claude Code run.
/appsec-advisor:verify-requirements --gate
```

Saved reports:

```bash
/appsec-advisor:verify-requirements --save
```

`--save` writes both Markdown and JSON reports under `docs/security/`.

## appsec-reviewer-cli

The CLI is the CI and automation wrapper around `verify-requirements`.

Run:

```bash
appsec-reviewer-cli review --diff origin/main --output security-review.md
```

Default behavior:

- invokes `/appsec-advisor:verify-requirements` headlessly
- writes `docs/security/.requirements-verification.json`
- renders the requested Markdown report
- exits `0` unless `--fail-on` is set and the deterministic gate fails

Requirements:

- Claude Code CLI on `PATH`
- `ANTHROPIC_API_KEY` or Claude Code subscription auth

GitLab CI:

```yaml
security_review:
  stage: test
  script:
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
      - name: Security review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          BASE_REF: ${{ github.base_ref }}
        run: |
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

The active standard is resolved in this order:

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

## Outputs and gates

Outputs:

- Hook: no review artifact; optional hook telemetry as described in [security-coach-skill.md](security-coach-skill.md).
- Agent: `.requirements-verification.json` in its configured output directory.
- Skill: `docs/security/.requirements-verification.json`; optional saved reports under `docs/security/`.
- CLI: requested Markdown report and `docs/security/.requirements-verification.json`.

Exit codes:

- `0`: review completed; advisory mode or no gate-violating finding.
- `1`: gate failed.
- `2`: usage, requirements-load, or verdict error.

Gate behavior:

- Skill: `--gate` enables non-zero exit on gating failures.
- CLI: `--fail-on must` blocks failed `MUST` requirements.
- CLI: `--fail-on partial` blocks failed or partial `MUST` requirements.
- Skill and CLI: `--priority-floor SHOULD` or `--priority-floor MAY` lowers the gate floor.

Pre-push example:

```bash
# .git/hooks/pre-push   (chmod +x)
#!/usr/bin/env bash
appsec-reviewer-cli review --diff origin/main --output /tmp/security-review.md --fail-on must
```

## CI security notes

Pull-request code is untrusted input. A CI job that runs the reviewer may expose an API key to attacker-controlled repository content.

Use CI review for private repositories, trusted same-repository pull requests, ephemeral runners, and dedicated low-limit CI API keys.

Do not use it for public fork pull requests with secrets, `pull_request_target` workflows that bypass secret withholding, or shared runners that retain sensitive state.

See [SECURITY.md](../SECURITY.md#known-issues--untrusted-repositories).

## Flag reference

### `/appsec-advisor:verify-requirements`

| Flag | Meaning |
|------|---------|
| `--base <ref>` | Compare against `<ref>`; default is the merge-base with upstream. |
| `--staged` | Review staged changes only (`git diff --cached`). |
| `--gate` | Exit non-zero on a gating failure; default is advisory. |
| `--gate-on fail\|partial` | Select what counts as gating; default is `fail`. |
| `--priority-floor MUST\|SHOULD\|MAY` | Lowest priority allowed to gate; default is `MUST`. |
| `--requirements <src>` | Use an `http(s)://` URL or local file path; unreadable explicit sources abort. |
| `--org-profile <path>` | Use this org profile for source resolution. |
| `--preset <name>` | Use a preset from the active org profile. |
| `--no-org-profile` | Ignore packaged or environment-pointed org profiles. |
| `--md` / `--json` / `--save` | Also save a report under `docs/security/`. |

### `appsec-reviewer-cli review`

| Flag | Meaning |
|------|---------|
| `--diff <ref>` | Base ref to diff against; required. |
| `--output <file>` | Report path; default is `security-review.md`. |
| `--requirements <src>` | Use an `http(s)://` URL or local file path; unreadable explicit sources abort. |
| `--fail-on must\|partial` | Make CI fail; omit for advisory mode. |
| `--priority-floor MUST\|SHOULD\|MAY` | Lowest priority allowed to gate. |

Design rationale: [proposal-dev-security-helper.md](proposal-dev-security-helper.md).
