# Comparison: `check-appsec-requirements` vs Claude Code `security-review`

This document compares two complementary security analysis capabilities: the appsec-plugin's **check-appsec-requirements** skill and Claude Code's built-in **security-review** skill.

## Overview

| Dimension | `check-appsec-requirements` | `security-review` |
|-----------|---------------------------|-------------------|
| **Type** | Compliance verification against a configurable baseline | Tactical vulnerability scanner with fixed rules |
| **Scope** | Entire repository (all requirements checked against codebase) | Individual files or file sets |
| **Rule source** | Team-defined YAML loaded from a remote URL (with plugin cache fallback) | 36 hardcoded rules across 7 Markdown rule files |
| **Customization** | Fully customizable — teams author their own requirements YAML | No customization — rules are fixed in the skill definition |
| **Output format** | Structured console report, optional Markdown and JSON export | One-liner console findings, no file export |

## Rule Coverage

### check-appsec-requirements

Rules are defined externally in a YAML file with structured metadata per requirement:

- Requirement ID (e.g., `SEC-AUTH-001`)
- Category (e.g., `SEC-AUTH`, `SEC-INJ`, `SEC-CRYPTO`)
- Title and description
- CWE and OWASP reference URLs
- Verification guidance

The reference baseline (`data/appsec-requirements-fallback.yaml`) contains **53 requirements across 10 categories**, but teams can add, remove, or modify requirements freely. Categories in the reference set:

| Category | Count | Focus |
|----------|-------|-------|
| SEC-AUTH | 8 | Authentication, session management |
| SEC-AUTHZ | 5 | Authorization, access control |
| SEC-INJ | 6 | Injection prevention |
| SEC-CRYPTO | 5 | Cryptography |
| SEC-DATA | 5 | Data protection |
| SEC-LOG | 4 | Logging and monitoring |
| SEC-ERR | 4 | Error handling |
| SEC-CONFIG | 6 | Security configuration |
| SEC-API | 5 | API security |
| SEC-SUPPLY | 5 | Supply chain security |

### security-review

Rules are fixed in 7 Markdown files under `~/.claude/skills/security-review/rules/`:

| Rule file | Rules | Covers |
|-----------|-------|--------|
| `auth.md` | 4 | JWT `none` algorithm, hardcoded credentials, missing authz middleware, broken session management |
| `authorization.md` | 6 | IDOR, missing authorization checks, privilege escalation, client-side authz, HTTP verb bypass, path traversal for authz bypass |
| `injection.md` | 7 | SQLi, command injection, XSS, XXE, open redirect, path traversal, template injection |
| `secrets.md` | 4 | Hardcoded secrets, committed `.env` files, secrets in logs, secrets in URLs |
| `crypto.md` | 5 | MD5/SHA1 for passwords, ECB mode, weak RNG, unsalted hashing, hardcoded IV/key |
| `hardening.md` | 10 | Missing security headers, TLS misconfiguration, excessive privileges, exposed JMX/debug ports, EOL software, insufficient logging, cache-control, directory listing, version disclosure |
| `input-validation.md` | 5 | Missing whitelist validation, blacklist-only validation, unsafe regex, missing type/range checks, missing size limits |

**Total: ~36 rules, not customizable.**

## Methodology

### check-appsec-requirements

1. **Load requirements** from remote URL (with plugin cache fallback). Aborts if unavailable.
2. **Verify each requirement** against the codebase by reading relevant source files and checking whether the requirement is implemented.
3. **Assign a status** to each requirement:
   - **PASS** — requirement is fully implemented with evidence
   - **PARTIAL** — requirement is partly implemented, gaps identified
   - **FAIL** — requirement is not implemented or implementation is inadequate
   - **UNVERIFIABLE** — cannot determine status from code alone (e.g., requires runtime testing)
4. **Render output** with before/after code snippets, VS Code deep links, and a remediation roadmap.

### security-review

1. **Read the target file(s)** and determine their content type.
2. **Selectively load rule files** — only rules relevant to the file's content are loaded (e.g., `crypto.md` is only loaded if the file contains hashing or encryption logic).
3. **Scan for violations** of each loaded rule.
4. **Output one-liner findings** sorted by severity (CRITICAL → HIGH → LOW → INFO).

## Output Comparison

### check-appsec-requirements output

```
SEC-AUTH-001  PASS      Multi-factor authentication support
  ✓ MFA implementation found in src/auth/mfa.ts:15
    Evidence: TOTP-based 2FA with backup codes

SEC-INJ-002  FAIL      Parameterized database queries
  ✗ String concatenation used in SQL queries
    src/db/users.ts:47 — before:
      const q = "SELECT * FROM users WHERE id = " + userId;
    Suggested fix:
      const q = "SELECT * FROM users WHERE id = $1";
    → vscode://file/path/to/src/db/users.ts:47

SEC-CRYPTO-003  PARTIAL   Strong password hashing
  ⚠ bcrypt used but cost factor is 8 (minimum 12 recommended)
    src/auth/password.ts:12

────────────────────────────────
Remediation Roadmap:
  1. [FAIL] SEC-INJ-002 — Parameterized database queries
  2. [PARTIAL] SEC-CRYPTO-003 — Increase bcrypt cost factor
────────────────────────────────
Summary: 1 pass, 1 partial, 1 fail, 0 unverifiable
```

### security-review output

```
Loading: injection.md, crypto.md

[SEC-INJ-SQLi-001] CRITICAL  src/db/users.ts:47  SQL query built via string concat
[SEC-CRY-HASH-001] HIGH      src/auth/password.ts:12  Weak bcrypt cost factor (8)

1 critical, 1 high, 0 low, 0 info
```

## Key Differences

### 1. Strategic vs Tactical

**check-appsec-requirements** answers: *"Does our codebase meet our security standards?"* — a governance question. It evaluates compliance against a defined baseline and produces auditable evidence.

**security-review** answers: *"Are there vulnerabilities in this file?"* — a tactical question. It finds concrete bugs in specific files during development.

### 2. Customizable vs Fixed

**check-appsec-requirements** is designed for teams to define their own security standards. The requirements YAML is fully owned by the team and can reflect organizational policies, regulatory requirements (PCI-DSS, SOC 2, HIPAA), or internal security guidelines.

**security-review** uses a fixed set of 36 rules. These cover common vulnerability classes well but cannot be extended or modified without editing the skill definition.

### 3. Whole-Repo vs File-Scoped

**check-appsec-requirements** scans the entire repository to verify each requirement, following code paths across multiple files if necessary.

**security-review** operates on individual files or small sets of files, making it fast and ideal for reviewing changes during development.

### 4. Evidence-Rich vs Concise

**check-appsec-requirements** provides detailed evidence: before/after code snippets, VS Code deep links, and a prioritized remediation roadmap.

**security-review** provides minimal one-liner findings designed for quick triage. Details are available on follow-up request.

### 5. Persistence vs Ephemeral

**check-appsec-requirements** can save results as Markdown reports or JSON files for archival, tracking trends over time, or feeding into GRC tools.

**security-review** outputs to the console only — no file persistence.

## When to Use Which

| Scenario | Recommended Tool |
|----------|-----------------|
| Quarterly security compliance audit | `check-appsec-requirements` |
| Reviewing a PR for security issues | `security-review` |
| Onboarding a new repository into the security program | `check-appsec-requirements` |
| Quick check of a config file for hardcoded secrets | `security-review` |
| Generating evidence for SOC 2 / PCI-DSS auditors | `check-appsec-requirements` |
| Spot-checking a developer's code during review | `security-review` |
| Tracking security posture improvements over time | `check-appsec-requirements` (with `--json` for trend data) |
| Finding injection vulnerabilities in a specific module | `security-review` |

## Using Both Together

The two tools are complementary, not competing. A recommended workflow:

1. **During development** — use `security-review` on changed files to catch vulnerabilities before they reach the main branch.
2. **At release gates** — run `check-appsec-requirements` to verify the full codebase meets the team's security baseline.
3. **For threat modeling** — use `create-threat-model --requirements` to incorporate requirements compliance into the STRIDE threat assessment (Phase 7b generates threats from FAIL requirements).

This layered approach combines fast tactical feedback during coding with comprehensive compliance verification at milestones.
