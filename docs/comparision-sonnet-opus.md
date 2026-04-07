# Threat Model Comparison: Sonnet vs Opus (appsec-plugin)

| Dimension | Sonnet (`/tmp/threat-model.md`) | Opus (`docs/security/threat-model-opus.md`) |
|-----------|------|------|
| Model | claude-sonnet-4-6 | claude-opus-4-6 (via appsec-plugin) |
| Generated | 2026-04-06T19:32:00Z | 2026-04-06T20:10:00Z |
| Analysis Duration | n/a | 12 min 42 s |
| Document Length | 1043 lines | 1070 lines |

---

## 1. Accuracy of Codebase Understanding

| Aspect | Sonnet | Opus | Verdict |
|--------|--------|------|---------|
| Angular version | Angular 17 | Angular 20 | **Opus correct** (package.json shows Angular 20) |
| Data stores identified | SQLite only | SQLite + MarsDB (NoSQL in-memory) | **Opus correct** - MarsDB used for reviews/orders |
| CI/CD awareness | Not mentioned | CodeQL SAST, ZAP DAST weekly, CycloneDX SBOM | **Opus significantly better** |
| Docker security posture | Not assessed | Distroless base image, UID 65532 non-root | **Opus identified positive controls Sonnet missed** |
| Deployment context | Generic | Specific (distroless/nodejs24-debian13, port 3000) | **Opus more precise** |

**Winner: Opus.** Opus demonstrates a more accurate and complete understanding of the actual codebase. Notably, discovering MarsDB as a second data store led directly to identifying the NoSQL injection threat (T-005) that Sonnet missed entirely.

---

## 2. Architecture Diagrams

Both produce C4-style Mermaid diagrams (System Context, Container, Technology, Security Assessment).

| Aspect | Sonnet | Opus |
|--------|--------|------|
| System Context actors | 4 (Anonymous, Authenticated, Admin, Attacker) | 3 (Trainee/Attacker, Admin/Instructor, Automated Scanner) |
| External services shown | Prometheus, B2B Client | Blockchain APIs, GitHub CDN |
| Container components | 7 | 8 (includes MarsDB, Chatbot Engine) |
| Trust boundary annotations | Mermaid comments | Mermaid comments |

Sonnet models the attacker as a separate actor (useful for threat analysis framing). Opus models external scanners and captures the blockchain/chatbot integrations that Sonnet omits. Both approaches are valid; Opus captures more of the actual architecture.

---

## 3. Security-Relevant Use Cases

| Sonnet (6 diagrams) | Opus (8 diagrams) |
|---------------------|-------------------|
| Authentication Flow | Authentication Flow |
| SQL Injection (Search + Login) | SQL Injection |
| File Upload / XXE | File Upload (XXE + SSRF) |
| Authorization and IDOR | Authorization / Access Control |
| Open Redirect and SSRF | Frontend Security (XSS) |
| Secret Management | Secret Management |
| | Input Validation Flow |
| | **B2B Order - RCE Flow** |

**Winner: Opus.** Two additional use case diagrams, and critically includes the B2B RCE flow which represents one of the most severe exploitation chains (remote code execution via `notevil` sandbox escape). Sonnet covers the B2B threat in its threat register but does not provide a visual attack flow.

---

## 4. Attack Surface Enumeration

| Metric | Sonnet | Opus |
|--------|--------|------|
| Entry points listed | 19 | 22 |
| Unauthenticated endpoints highlighted | 11 of 19 | Not explicitly counted |

Opus identifies 3 additional attack surface entries that Sonnet misses:
- `GET /rest/admin/application-configuration` (unauthenticated config disclosure)
- `GET /rest/admin/application-version` (version disclosure)
- `GET /snippets/:challenge` (challenge source code exposure)
- `GET /rest/user/change-password` (password in query string)
- `POST /rest/chatbot/respond` (chatbot injection)

**Winner: Opus** - broader and more complete attack surface mapping.

---

## 5. Threat Register Comparison

### Quantitative

| Metric | Sonnet | Opus |
|--------|--------|------|
| Total threats | 24 | 18 |
| Critical | 6 | 6 |
| High | 8 | 6 |
| Medium | 7 | 5 |
| Low | 3 | 1 |
| STRIDE Spoofing | 4 | 3 |
| STRIDE Tampering | 5 | 5 |
| STRIDE Repudiation | 2 | 1 |
| STRIDE Information Disclosure | 7 | 5 |
| STRIDE Denial of Service | 2 | 2 |
| STRIDE Elevation of Privilege | 4 | 2 |

### Qualitative: What Each Found That The Other Missed

**Opus-only findings:**
- **NoSQL injection in MarsDB product reviews** (T-005, Critical) - mass review tampering via operator injection in `_id` field. This is a significant finding: a Critical-rated injection vector that Sonnet entirely overlooked because it did not identify MarsDB as a data store.
- **Password change via GET with credentials in URL** (T-006) - password exposed in query string, server logs, and browser history.
- **YAML bomb DoS** (T-015) - exponential expansion within 200KB upload limit.
- **Outdated dependencies as explicit threat** (T-017) - jsonwebtoken 0.4.0, express-jwt 0.1.3, sanitize-html 1.4.2 cataloged with current versions.

**Sonnet-only findings (as separate threats):**
- Prometheus metrics exposure (T-015)
- Basket IDOR (T-016)
- Missing security event logging (T-017)
- Rate limit bypass via X-Forwarded-For (T-018)
- XSS via last login IP reflection (T-019)
- Wildcard CORS (T-020)
- Swagger UI exposure (T-021)
- Open redirect (T-022)
- bypassSecurityTrustHtml in feedback carousel (T-023)
- Broad DoS via missing rate limits (T-024)

### Consolidation vs Granularity

Sonnet creates separate threat entries for each exposure: metrics, Swagger, FTP, logs, and encryption keys are 4-5 separate threats. Opus consolidates these into a single threat (T-010: "Static File Endpoints - Information Disclosure") covering all unauthenticated file-serving endpoints. 

Sonnet's approach inflates the threat count but provides more granular tracking. Opus's approach avoids noise and focuses remediation attention where it matters most. For a security team, **Opus's consolidation is more actionable** - the remediation is the same (add auth to all sensitive endpoints), so splitting them adds tracking overhead without adding insight.

### Threat Scenario Quality

Both models provide precise code references (file paths + line numbers) and describe exploitation steps clearly. However:

- **Opus** provides richer exploitation narratives. For example, Opus's T-003 (search SQLi) explicitly describes the UNION payload structure, notes that MD5 hashes are "crackable offline with GPU hardware in seconds," and explains the chaining from SQLi to credential compromise. Sonnet's equivalent (T-006) describes the same flow but in slightly less operational detail.
- **Opus** better identifies threat chaining: T-003 explicitly notes the dependency on T-004 (MD5 hashing) to escalate the SQLi from data exposure to credential compromise.
- **Sonnet** provides more explicit STRIDE category justification but sometimes miscategorizes (T-020 "Wildcard CORS" is labeled "Denial of Service" when it's primarily an Information Disclosure / Tampering concern).

**Winner: Mixed.** Sonnet finds more individual issues (24 vs 18). Opus finds fewer but higher-signal threats, including the MarsDB NoSQL injection that Sonnet missed. The 6 Critical-rated threats are substantively similar across both models. Opus's threat chaining analysis is superior. Sonnet's broader coverage captures more edge cases.

---

## 6. Security Controls Assessment

| Metric | Sonnet | Opus |
|--------|--------|------|
| Controls assessed | ~24 | ~30 |
| Positive controls identified | Lock file, Morgan logging, TOTP 2FA, partial Sequelize ORM | Lock file, Morgan logging, TOTP 2FA, partial Sequelize ORM, **CodeQL SAST**, **ZAP DAST**, **CycloneDX SBOM**, **Docker non-root user**, **Distroless base image**, env var usage |

**Winner: Opus decisively.** Identifying existing positive security controls is a hallmark of a mature threat model. Opus recognizes 6 additional adequate/partial controls that Sonnet misses, including CI/CD security tooling (CodeQL, ZAP), container hardening (distroless, non-root), and SBOM generation. A threat model that only lists failures without acknowledging existing defenses provides an incomplete risk picture and can lead to misallocated remediation effort.

---

## 7. Mitigation Register

| Metric | Sonnet | Opus |
|--------|--------|------|
| Total mitigations | 18 | 15 |
| With code examples | All 18 | All 15 |
| OWASP/CWE references | All 18 | All 15 |
| Effort estimates | All | All |
| Priority levels | Critical: 5, High: 7, Medium: 6 | Critical: 5, High: 5, Medium: 5 |

### Mitigation Quality Comparison

Both provide actionable before/after code snippets, OWASP cheat sheet references, and CWE identifiers. Key differences:

- **Opus M-003** (Replace MD5 with KDF) recommends Argon2id with explicit parameter tuning (`memoryCost: 65536, timeCost: 3, parallelism: 4`) and includes a migration path (re-hash on login). Sonnet's M-009 recommends bcrypt with a work factor of 12. Both are valid; Opus's recommendation follows the OWASP 2024 guidance preferring Argon2id.
- **Opus M-004** (NoSQL injection) provides a complete ownership-checking implementation that Sonnet cannot provide because it didn't identify the vulnerability.
- **Opus M-005** (Rate limit fix) correctly identifies that the rate limit window should also be reduced from 100 to 10 requests, which Sonnet's M-014 does not.
- **Opus M-015** (Dependency upgrades) provides specific target versions and API migration notes for express-jwt v8. Sonnet doesn't have an equivalent mitigation.
- **Sonnet M-010** (Replace notevil) recommends redesigning B2B orders to JSON schema validation with AJV - a strong architectural recommendation not in Opus.
- **Sonnet M-007** (Zip Slip prevention) provides a path traversal validation pattern not in Opus.

**Winner: Slight edge to Opus** for mitigation precision, but Sonnet covers more ground with its higher mitigation count. The gap is small - both produce production-quality remediation guidance.

---

## 8. Out of Scope Documentation

| Sonnet (9 items) | Opus (7 items) |
|------------------|----------------|
| WebSocket / chatbot | Web3/Blockchain components |
| Web3 / NFT components | Chatbot training data security |
| Cryptomining challenge mechanics | Kubernetes / cloud deployment |
| Frontend Angular unit tests | Third-party dependency CVE inventory |
| Third-party dependency CVEs | CTF challenge infrastructure |
| Infrastructure deployment hardening | Frontend Angular component security |
| i18n / translation content | Vagrant deployment |
| Prometheus alerting | |
| GDPR / data retention | |

Both appropriately scope their analysis. Sonnet documents more out-of-scope items, which provides better audit trail. Opus mentions Vagrant deployment specifically (demonstrating it noticed the vagrant/ directory).

---

## 9. Overall Value Assessment

### Scoring Summary (1-5 scale)

| Dimension | Sonnet | Opus |
|-----------|--------|------|
| Codebase accuracy | 3 | 5 |
| Architecture understanding | 3.5 | 4.5 |
| Threat identification breadth | 4.5 | 3.5 |
| Threat identification depth | 3.5 | 4.5 |
| Threat chaining / compound risk | 3 | 4.5 |
| Security controls assessment | 3 | 5 |
| Mitigation quality | 4 | 4.5 |
| Actionability for a security team | 3.5 | 4.5 |
| False positive rate | Low | Low |
| **Overall** | **3.5** | **4.5** |

### Key Differentiators

1. **Discovery of MarsDB and NoSQL injection (Opus)** - This is the single most impactful difference. Opus correctly identified a second data store that Sonnet missed entirely, leading to a Critical-rated injection finding. This demonstrates deeper codebase exploration and better architectural comprehension.

2. **Existing positive controls (Opus)** - Opus's identification of CodeQL, ZAP, CycloneDX, distroless images, and non-root Docker execution shows a balanced assessment that acknowledges defenses, not just failures. This is essential for accurate risk prioritization.

3. **Threat granularity trade-off (Sonnet)** - Sonnet's 24 threats vs 18 is partly an artifact of splitting consolidated issues into individual entries. This gives better tracking granularity but can create noise. Sonnet does catch some edge cases (last-login-IP XSS, open redirect, GDPR data erasure) that Opus omits.

4. **Accuracy (Opus)** - Sonnet states Angular 17; Opus correctly identifies Angular 20. For a threat model to be credible to a development team, factual accuracy matters.

### Cost-Value Consideration

Opus took a recorded 12 min 42 s of analysis time (Sonnet's duration was not recorded). Opus models are more expensive per token than Sonnet. However, the higher accuracy, deeper findings (MarsDB NoSQL injection), and more complete controls assessment likely justify the cost premium for security-critical assessments. For a production codebase where a missed injection vector could mean a data breach, the incremental cost of Opus is negligible compared to the value of a more complete threat model.

### When to Use Each

- **Use Opus** when: performing a formal security assessment, preparing for an audit, evaluating production deployment readiness, or when accuracy and depth matter more than speed and cost.
- **Use Sonnet** when: performing a rapid initial scan, triaging a new codebase, running frequent delta assessments on code changes, or when budget constraints require lower per-run cost. Sonnet's broader (if shallower) coverage still catches the majority of critical issues.

### Recommendation

For the OWASP Juice Shop codebase, the **Opus threat model provides higher value** due to its superior codebase accuracy, discovery of the MarsDB NoSQL injection vector, more complete security controls assessment, and better threat consolidation. The Sonnet model remains a strong artifact that identifies the same core critical issues but would benefit from a follow-up pass to correct factual inaccuracies and identify the missed NoSQL attack surface.

---

*Comparison performed 2026-04-06. Both threat models were generated by the appsec-plugin using the STRIDE methodology against the same OWASP Juice Shop repository at the same commit.*
