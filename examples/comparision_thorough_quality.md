# Thorough Threat Model — Quality Comparison

**Opus vs Sonnet** (both at `thorough` depth, analyzing OWASP Juice Shop). Cost, token usage, and runtime are **excluded** — this is a quality-only comparison.

## 1. Coverage Breadth

| Dimension | Thorough-Opus | Thorough-Sonnet |
|---|---|---|
| Total threats | **42** | 30 |
| Critical | 9 | **10** |
| High | **18** | 15 |
| Medium | 9 | 4 |
| Low | **6** | 1 |
| Unauth entry points | 7 | **22** |
| Auth entry points | 5 | **13** |
| Components analyzed | 8 | 8 (+ Authentication Service decomposed) |
| Attack walkthroughs | **5** | 4 |

**Winner: Opus** on sheer threat volume; **Sonnet** on attack-surface enumeration and component decomposition.

## 2. Severity Calibration

Both ratings are defensible. Notable differences:

- **Opus** is more conservative: MD5 rated **High** (T-003), XSS variants **Critical** (T-005, T-006), Zip Slip **Critical** (T-008).
- **Sonnet** is more aggressive: client-controlled role assignment as **Critical** (T-025), brute-force login **Critical** (T-005), MD5 **High** (T-004), Zip Slip **High** (T-017).

Opus keeps the Critical tier tight around directly-exploitable RCE/auth-bypass chains. Sonnet elevates business-logic (role tampering) and rate-limit gaps to Critical, which is defensible for this app but slightly inflates the tier.

**Winner: Opus** — cleaner discrimination between "game over" and "serious."

## 3. Critical Threats — Overlap & Unique

| Critical Threat | Opus | Sonnet |
|---|---|---|
| Hardcoded RSA private key → JWT forgery | T-007 | T-001 |
| SQLi — login bypass | T-001 | T-003 |
| SQLi — unauthenticated search/dump | T-002 | T-006 |
| JWT `alg:none` bypass | — | **T-002** |
| MD5 + offline crack | T-003 | — (High, T-004) |
| B2B eval RCE | T-004 | T-020 |
| SSTI/eval RCE in username | — | **T-022** |
| Stored/reflected XSS via `bypassSecurityTrustHtml` | T-005, T-006 | T-013 |
| Zip Slip | T-008 | — (High, T-017) |
| XXE | T-009 | — (High, T-016) |
| Brute-force / no account lockout | — | **T-005** |
| Unauth management endpoints (`/ftp`, `/encryptionkeys`, `/support/logs`) | — (split: T-018, T-025) | **T-009** (consolidated) |
| Client-controlled role assignment (`role:"admin"` in PUT /api/Users) | — | **T-025** |

**Unique Critical to Opus (4):** MD5 offline crack as Critical; two distinct XSS sinks as separate Criticals; Zip Slip; XXE.
**Unique Critical to Sonnet (4):** `alg:none` bypass, SSTI, brute-force login, role-tampering.

**Sonnet catches two devastating threats Opus misses entirely at Critical level:** JWT `alg:none` (library-level auth bypass) and direct role-escalation via PUT request. These are among the most iconic Juice Shop vulnerabilities.

**Winner: Split** — Opus wider on injection/file-handling; Sonnet sharper on auth/authorization logic.

## 4. Technical Depth — Code Specificity

Both use `vscode://` clickable links with file:line refs and CWE IDs in every threat row. Both include exact payload strings.

- **Opus** average: denser prose per threat, often chains multiple CWEs into one finding (e.g., T-004 cites CWE-327 **and** CWE-94 in one row covering alg:none → eval RCE as a compound chain).
- **Sonnet** average: more threats but each tightly scoped to a single CWE, making them easier to triage individually.

Example — same SQLi on login:

> **Opus T-001:** "Attacker sends `POST /api/Users/login` with email `' OR 1=1--` — raw string interpolation at `routes/login.ts:34` yields `SELECT * FROM Users WHERE email = '' OR 1=1--'` returning the first user row (typically admin). CWE-89."

> **Sonnet T-003:** "Raw SQL injection at `routes/login.ts:34` — `SELECT * FROM Users WHERE email = '${req.body.email}'` allows `' OR '1'='1` to log in as any user or dump all credentials. CWE-89."

Opus provides the resulting SQL shape; Sonnet provides the source template. Equivalent quality.

**Winner: Tie.**

## 5. Mitigation Quality

- **Opus:** 27 mitigations (M-001 … M-027) across P1/P2/P3 tiers, each with effort hints and explicit before/after code where relevant (e.g., M-021 shows GitHub Action SHA pinning).
- **Sonnet:** 28 mitigations (M-001 … M-028) across P1/P2/P3/**P4** tiers. Longer mitigation sections on average with more remediation code examples.

Both cross-link mitigations ↔ threats bidirectionally. Sonnet's P4 "Backlog" tier is a nice touch for residual items (CSP, hardening).

**Winner: Slight Sonnet** — the P4 tier and generally richer code snippets.

## 6. Business Logic & Context Awareness

| Business-logic threat | Opus | Sonnet |
|---|---|---|
| IDOR on basket/memories | T-019 | T-007 |
| Wallet negative-balance tampering | — | **T-027** |
| Role assignment on user PUT | — | **T-025** |
| Change-password without current password | T-029 | T-026 |
| Open redirect as phishing vector | T-015 | T-030 |
| NoSQL injection on review update | T-020 | T-010 |
| CORS wildcard → CSRF synergy | — | **T-011 + T-012 chain** |
| Challenges endpoint leaks CTF flags | T-032 | — |
| Product field over-exposure (`deletedAt`, internal IDs) | T-030 | — |

**Winner: Sonnet** — catches role escalation and wallet tampering (both iconic Juice Shop business-logic bugs) that Opus misses. Opus finds more peripheral info-disclosure endpoints.

## 7. Infrastructure & Supply-Chain

| Concern | Opus | Sonnet |
|---|---|---|
| Floating GH Action tags | **T-027** | Noted as strength (SHA-pinned) |
| Git-URL dependency (`frisby`) | **T-036** | — |
| `--unsafe-perm` in Dockerfile | **T-041** | — |
| CodeQL not a required check | **T-042** | — |
| Outdated deps (express-jwt 0.1.3 etc.) | Implicit via T-004 | **T-024** (explicit with versions) |
| Distroless image posture | Noted | Noted |
| Hardcoded Alchemy API key | — | **T-028** |
| Mandatory code-review gate | — | T-029 |

**Winner: Opus** — more CI/CD and build-chain findings (4 unique). Sonnet has depth on dependency versions and third-party key exposure.

## 8. Injection / Encoding Variant Coverage

| Variant | Opus | Sonnet |
|---|---|---|
| SQLi (login) | ✅ T-001 | ✅ T-003 |
| SQLi (search, unauth) | ✅ T-002 | ✅ T-006 |
| XSS (multiple sinks) | ✅ T-005, T-006 | ✅ T-013 |
| NoSQL injection | ✅ T-020 | ✅ T-010 |
| XXE | ✅ T-009, T-023 | ✅ T-016 |
| Zip Slip | ✅ T-008 | ✅ T-017 |
| YAML bomb | — | ✅ **T-018** |
| ZIP bomb | ✅ T-024 | — |
| SSRF (profile image) | ✅ T-021 | ✅ T-019 (+ chatbot training URL) |
| SSTI / eval in username | — | ✅ **T-022** |
| Open redirect | ✅ T-015 | ✅ T-030 |
| CSP header injection | — | ✅ **T-023** |
| Null-byte path traversal on `/ftp` | ✅ T-026 | — |
| File upload extension bypass | ✅ T-022 | — |
| LIKE-prefix full-table-scan DoS | ✅ T-013 | — |

Both cover the core variants. Opus wins on DoS/file-upload variants; Sonnet wins on SSTI, YAML bomb, and CSP injection.

**Winner: Slight Opus** (more variant diversity), but **Sonnet catches SSTI**, which is a high-signal finding.

## 9. Authentication / Crypto Analysis

| Topic | Opus | Sonnet |
|---|---|---|
| Hardcoded RSA key | ✅ T-007 | ✅ T-001 |
| Hardcoded HMAC secret | ✅ T-010 (separate) | Merged into T-004 |
| `alg:none` bypass | ❌ **missed** | ✅ **T-002** |
| MD5 unsalted hashing | ✅ T-003 (Critical) | ✅ T-004 (High) |
| JWT in `localStorage` + XSS synergy | ✅ T-014, T-039 | ✅ T-014 |
| No account lockout / brute-force | — | ✅ **T-005** |
| X-Forwarded-For rate-limit bypass | ✅ T-033 | Implicit |
| Change-password without current pw | ✅ T-029 | ✅ T-026 |
| No email verification | ✅ T-028 | Implicit |

**Winner: Sonnet** — catches `alg:none`, the single most iconic JWT library bug in this codebase. Opus misses it entirely despite analyzing the same `jws.verify` call.

## 10. Clarity, Structure & Reasoning

Both files share the same backbone: Management Summary → Worst-Case Scenarios → Critical Attack Chain → System Overview → Architecture Diagrams → Architecture Assessment → Attack Walkthroughs → Assets → Attack Surface → Trust Boundaries → Controls → Threat Register → Critical Findings → Mitigation Register → Out of Scope → Run Statistics.

- **Sonnet** additionally decomposes the Authentication Service at C4 component level (§2.3) — Opus skips component-level decomposition.
- **Opus** provides 5 attack walkthroughs, Sonnet 4. Opus walkthroughs include more step-by-step curl commands.
- Both produce Mermaid attack-chain diagrams. Opus: 3 chains (unauth full compromise, offline JWT forgery → RCE, XSS session harvest). Sonnet: 2 chains (unauth extraction → takeover, authenticated RCE paths).

**Winner: Tie.** Opus: more attack-chain narratives. Sonnet: component-level decomposition.

## 11. False Positives / Questionable Findings

- **Opus** — all 42 threats appear legitimate. Some Medium/Low findings (T-030 product field exposure, T-032 challenges endpoint) are borderline but accurate.
- **Sonnet** — T-005 "brute-force login" as **Critical** is arguable (likelihood ≠ impact escalation); T-025 "role assignment" assumes Sequelize doesn't strip the field — this should be verified in code. Otherwise clean.

**Winner: Opus** — marginally more conservative, fewer findings that require verification.

## 12. Notable Blind Spots

**Opus misses:**
- JWT `alg:none` bypass (critical library flaw)
- SSTI / eval in username field
- Client-controlled role assignment
- Wallet balance negative-amount abuse
- YAML bomb
- CSP header injection
- CORS wildcard explicit finding

**Sonnet misses:**
- Floating GitHub Action tags, `--unsafe-perm`, CodeQL gate
- Git-URL dependency
- File-upload extension bypass
- LIKE-prefix query DoS
- Null-byte path traversal on `/ftp`
- ZIP bomb (has YAML bomb instead)
- CSRF protection gap (has it as Medium; Opus as Low)
- Challenges endpoint flag leakage
- Prometheus metrics DoS reconnaissance angle (only basic info-disclosure)

## Verdict

**Sonnet is higher quality for security-impact triage.** It catches the three most damaging bugs Opus misses — `alg:none`, SSTI, and role-escalation — each of which individually ends the engagement. Its architecture assessment is also one level deeper (component decomposition).

**Opus is higher quality for breadth and infrastructure hygiene.** 12 more threats, stronger CI/CD and supply-chain coverage, and a tighter severity-tier discipline. More attack walkthroughs with executable payloads.

**By scenario:**

| Scenario | Preferred |
|---|---|
| Executive/risk briefing — impact-first | **Sonnet** |
| Developer remediation backlog — breadth-first | **Opus** |
| Auth / crypto audit | **Sonnet** |
| Infra / DevSecOps audit | **Opus** |
| Pen-test prep (exploit-ready chains) | **Opus** (more walkthroughs) |
| Architecture review / threat modeling exercise | **Sonnet** (component decomposition) |
| Compliance mapping (comprehensive register) | **Opus** (42 threats) |

**Overall quality:** neither dominates. If forced to pick one for a single deliverable where missing findings is unacceptable, **run both and merge** — Opus's volume plus Sonnet's three critical auth/authz catches produces the strongest combined model. If only one: **Sonnet**, because the threats it uniquely finds (`alg:none`, SSTI, role assignment) are categorically more severe than those Opus uniquely finds.
