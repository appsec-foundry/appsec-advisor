# Security review for the code you're writing

Checks the code you wrote against your team's security requirements and tells you what to fix. Works with no setup — if no company catalog is configured it falls back to a built-in best-practices baseline. Advisory by default; a CI gate is opt-in.

## Components

Three things you use. They share the same requirements catalog, so the advice is consistent wherever it shows up.

| Component | Type | What it does | Use it for |
|-----------|------|--------------|------------|
| [Security steering](#security-steering) | Hook | Injects the relevant requirement into Claude's context *before* it answers a security-related prompt. Automatic, never blocks. | proactive guidance while you code |
| [verify-requirements](#verify-requirements) | Skill | Reviews the change you just made, in your session. | an on-demand read of your diff |
| [appsec-reviewer](#appsec-reviewer) | CLI | Runs that review in CI and writes a Markdown report (and can fail the build). | merge-request reports, or a gate |

Steering is *proactive* (before you write), verify-requirements is *on-demand* (after you write), and appsec-reviewer is the *CI* form of the same review.

Both the skill and the CLI are front-ends: they dispatch the same worker agent, `appsec-requirements-verifier`, which does the actual grading. You never invoke that agent directly, so it has no section of its own.

## Security steering

Proactive, passive guidance. A `UserPromptSubmit` hook that prepends the applicable requirements when a prompt is security-relevant (auth, crypto, SQL, secrets, IaC, …) and stays silent otherwise.

Enable per session or per project:

```bash
APPSEC_COACH=1 claude
```

```jsonc
// config.json
{ "security_coach": { "enabled": true } }
```

The prompt *"implement the OAuth refresh-token endpoint"* then reaches the model with the auth requirements already in context:

```
[auth] short-lived tokens with rotation on refresh; validate
issuer/audience/signature/expiry on every JWT check; MFA for admin paths.
Applicable requirements:
  - BP-AUTH-SESSION-COOKIE (MUST): Issue session cookies with HttpOnly, Secure…
```

## verify-requirements

Reviews your current change on demand. Diffs your branch against its merge-base, picks the requirements the change touches, and grades only those.

```
/appsec-advisor:verify-requirements
```

```
AppSec Requirements — Change Verification
Base   : origin/main..HEAD   (3 files changed)
Scope  : 2 in-scope of 6 candidate requirements

  ● [FAIL] MUST  BP-INJ-SQL-PARAM  Parameterized SQL Queries
  Finding : raw request input reaches sequelize.query() in src/routes/search.ts:23
  Fix     : bind the term — sequelize.query(sql, { replacements: { term } })
  Effort  : M
```

Exits cleanly (advisory). `--base <ref>` sets the comparison point, `--staged` reviews staged changes, `--gate` makes it exit non-zero on a failure. Full flags: [reference](#flag-reference).

## appsec-reviewer

The same review as a CLI command for pipelines. Needs the Claude Code CLI on `PATH` and `ANTHROPIC_API_KEY` (or a subscription login — see [headless-mode.md](headless-mode.md)).

**Advisory report (default)** — writes the report, leaves the pipeline green.

```yaml
# GitLab CI
security_review:
  stage: test
  script:
    - appsec-reviewer review --diff origin/main --output security-review.md
  artifacts:
    paths:
      - security-review.md
```

```yaml
# GitHub Actions — hardened; see the security note below
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
          appsec-reviewer review --diff "origin/$BASE_REF" --output security-review.md
      - uses: actions/upload-artifact@<commit-sha>
        with: { name: security-review, path: security-review.md }
```

The report:

```markdown
# Security Review — change verification

| Checked against | built-in best-practices baseline |
| In-scope        | 2 of 6 candidates |
| Result          | 🔴 1 fail · 🟡 1 partial · 🟢 0 pass |

## What to fix
### 🔴 FAIL · MUST · BP-INJ-SQL-PARAM
raw request input reaches sequelize.query() at src/routes/search.ts:23
**Fix:** bind the term via replacements …
```

**Gate (opt-in)** — add `--fail-on` to exit non-zero (red MR check) when a requirement at or above the floor fails.

```yaml
script:
  - appsec-reviewer review --diff origin/main --output security-review.md --fail-on must
```

`--fail-on must` blocks on a failed `MUST`; `--fail-on partial` also on partials; `--priority-floor should` lets `SHOULD` gate. Exit codes: `0` clean, `1` gating failure, `2` error (e.g. a named `--requirements` source that couldn't load).

> **Security note — don't hand this secret to untrusted PRs.** The job holds an API key *and* runs an agent over the PR's code, which is attacker-controllable on an external PR. The plugin treats a scanned repo as untrusted input, so a crafted PR could use prompt injection to read the key from the environment ([SECURITY.md](../SECURITY.md#known-issues--untrusted-repositories)). Safe for **private repos with trusted contributors** (same-repo `pull_request`); **not** for fork / public PRs. Never use `pull_request_target` to work around forks not getting secrets — that withholding is the safety mechanism. Prefer ephemeral runners and a dedicated CI key with a spend limit.

**Pre-push hook** — same command, local. Use pre-push (not pre-commit) so it runs once per push.

```bash
# .git/hooks/pre-push   (chmod +x)
#!/usr/bin/env bash
appsec-reviewer review --diff origin/main --output /tmp/security-review.md --fail-on must
```

## Requirements source

Uses your configured company catalog if there is one, else the bundled best-practices baseline. Override with `--requirements <src>`, where `<src>` is an `http(s)://` URL or a local file path. No `http(s)` scheme means it's read as a file (relative to where you run it); an unreadable source aborts the run instead of silently falling back — the same contract the threat-model tooling uses.

```bash
/appsec-advisor:verify-requirements --requirements ./security/our-requirements.yaml
/appsec-advisor:verify-requirements --requirements https://reqs.example.com/appsec.yaml
appsec-reviewer review --diff origin/main --output security-review.md --requirements ./security/reqs.yaml
```

For org-wide defaults, set the source in the org profile — see [org-profiles.md](org-profiles.md) and [security-requirements-audit-skill.md](security-requirements-audit-skill.md). A catalog is YAML, and the IDs are yours to name (no fixed prefix):

```yaml
source: acme-appsec
categories:
  - id: ACME-AUTH
    title: Authentication
    requirements:
      - id: ACME-AUTH-01
        priority: MUST          # MUST | SHOULD | MAY
        text: Passwords must be stored with Argon2id or bcrypt.
        url: https://wiki.acme.internal/appsec/auth
```

With no source configured and none passed, the check runs against `data/appsec-bestpractices-baseline.yaml` (OWASP-derived: auth, access control, injection, crypto, secrets, headers, validation, logging, dependencies).

## Flag reference

`/appsec-advisor:verify-requirements`

| Flag | Meaning |
|------|---------|
| `--base <ref>` | compare against `<ref>` (default: merge-base with upstream) |
| `--staged` | review staged changes only (`git diff --cached`) |
| `--gate` | exit non-zero on a gating failure (default: advisory) |
| `--gate-on fail\|partial` | what counts as gating (default `fail`) |
| `--priority-floor MUST\|SHOULD\|MAY` | lowest priority allowed to gate (default `MUST`) |
| `--requirements <src>` | `http(s)://` URL or local file path (no scheme ⇒ file; aborts if unreadable) |
| `--md` / `--json` / `--save` | also save a report under `docs/security/` |

`appsec-reviewer review`

| Flag | Meaning |
|------|---------|
| `--diff <ref>` | base ref to diff against (required) |
| `--output <file>` | report path (default `security-review.md`) |
| `--requirements <src>` | `http(s)://` URL or local file path (no scheme ⇒ file; aborts if unreadable) |
| `--fail-on must\|partial` | make CI fail (omit = advisory, exit 0) |
| `--priority-floor MUST\|SHOULD\|MAY` | lowest priority allowed to gate |

Design rationale: [proposal-dev-security-helper.md](proposal-dev-security-helper.md).
