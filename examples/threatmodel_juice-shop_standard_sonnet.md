# Threat Model — OWASP Juice Shop

> | | |
> |---|---|
> | **Project** | OWASP Juice Shop v19.2.1 |
> | **Description** | Probably the most modern and sophisticated insecure web application |
> | **Author** | Björn Kimminich (bjoern.kimminich@owasp.org) |
> | **License** | MIT |
> | **Repository** | https://github.com/juice-shop/juice-shop |
> | **Homepage** | https://owasp-juice.shop |
> | **Runtime** | Node.js 24, Express 4.22, Angular 20, SQLite (Sequelize 6), MarsDB, TypeScript |
> | **Tags** | web security, owasp, pentest, ctf, vulnerable, bodgeit, awareness |

---

## Changelog

| Version | Date | Mode | Components Re-analyzed | Key Changes |
|---------|------|------|------------------------|-------------|
| 1 | 2026-04-14 | full | auth-service, rest-api, frontend-spa, file-upload, admin-panel | Initial assessment — 30 threats identified across 5 components |

---

## Table of Contents

1. [Management Summary](#management-summary)
2. [Critical Attack Chain](#critical-attack-chain)
3. [System Overview](#1-system-overview)
4. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Container Diagram](#22-container-diagram)
   - [2.3 Technology Architecture](#23-technology-architecture)
   - [2.4 Security Architecture Assessment](#24-security-architecture-assessment)
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

🔴 **Critical security posture — this application has multiple independently exploitable critical vulnerabilities accessible without authentication.**

- **Unauthenticated SQL injection** on both the login and product search endpoints allows full database extraction and authentication bypass without credentials
- **Hardcoded RSA private key** in public source code enables offline forgery of administrator tokens for any user account
- **Remote code execution** is achievable by any registered user via prototype pollution in the B2B order processing endpoint
- **Systemic XSS** across the Angular frontend from disabled sanitizer calls enables session theft at scale

This assessment covers an intentionally vulnerable training application. In a real production system, these five Critical findings would represent an immediate breach — any single one would yield full application compromise. All five have concrete, one-to-five-line fixes documented in Section 9.

### Top Threats

| Severity | ID | Description | Impact | Mitigation | Effort |
|----------|-----|-------------|--------|------------|--------|
| 🔴 | [T-001](#t-001) | Hardcoded RSA private key — offline JWT forgery | Full authentication bypass, any role | [M-001](#m-001) — Env var for key | Medium |
| 🔴 | [T-002](#t-002) | SQL injection on login — auth bypass + DB dump | Admin access, credential theft | [M-002](#m-002) — Parameterized queries | Medium |
| 🔴 | [T-003](#t-003) | JWT alg:none bypass via express-jwt 0.1.3 | Authentication bypass without key | [M-003](#m-003) — Upgrade + algorithm enforcement | Low |
| 🔴 | [T-007](#t-007) | Unauthenticated SQL injection on search | Full user table + schema extraction | [M-002](#m-002) — Parameterized queries | Medium |
| 🔴 | [T-008](#t-008) | RCE via notevil sandbox escape (B2B orders) | Server shell access | [M-007](#m-007) — Remove eval; use schema validation | High |
| 🟠 | [T-004](#t-004) | MD5 password hashing — rainbow table crackable | Mass credential compromise | [M-004](#m-004) — Upgrade to bcrypt | Medium |
| 🟠 | [T-009](#t-009) | NoSQL injection on order tracking ($where) | All order data enumeration | [M-008](#m-008) — Remove $where | Medium |
| 🟠 | [T-010](#t-010) | IDOR — basket and data export ownership bypass | Cross-user PII access | [M-009](#m-009) — Ownership check | Medium |
| 🟠 | [T-016](#t-016) | Stored XSS via bypassSecurityTrustHtml in search | Session theft from all users | [M-014](#m-014) — Remove sanitizer bypass | Medium |
| 🟠 | [T-020](#t-020) | XXE in XML upload — arbitrary file read | Server file system access | [M-016](#m-016) — Disable noent | Low |

_Legend: 🔴 Critical · 🟠 High_

### ⚠ Worst Case Scenarios

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

**Scenario 1 — Unauthenticated full compromise:**
An attacker visits the public GitHub repository, reads the hardcoded RSA private key from `lib/insecurity.ts:24`, and uses it to sign a JWT with `role: admin`. They send this token to any admin-only endpoint and gain full administrative access to the application — including access to all user data — without ever logging in.

**Scenario 2 — Mass credential exfiltration via unauthenticated SQL injection:**
An attacker submits a UNION-based SQL injection to `GET /rest/products/search?q=` and extracts the full `Users` table including email addresses and MD5-hashed passwords for every registered user. Because MD5 has no salt, the hashes crack within minutes against public rainbow tables, yielding plaintext passwords for reuse across services.

**Scenario 3 — Authenticated RCE to server shell:**
A registered user sends a crafted `orderLinesData` payload to `POST /b2b/v2/orders` that escapes the `notevil` sandbox via prototype pollution. The payload executes arbitrary Node.js code on the server, granting the attacker a reverse shell with the privileges of the application process.

**Scenario 4 — Stored XSS to admin session theft:**
An attacker registers an account with an XSS payload as their username. When any admin visits the administration panel, the unsanitized username is injected into the DOM via `bypassSecurityTrustHtml`. The payload reads the admin's JWT from `localStorage` and exfiltrates it to the attacker — complete admin session compromise.

→ See [Critical Attack Chain](#critical-attack-chain) for the visual exploitation flows.

</blockquote>

### Architecture Assessment

| Severity | Layer | Defect | Consequence | Enables |
|----------|-------|--------|-------------|---------|
| 🔴 | Data | No parameterized queries in login and search routes | Any input crafting a SQL payload yields DB access | [T-002](#t-002) — SQLi login, [T-007](#t-007) — SQLi search |
| 🔴 | Identity | RSA private key hardcoded in public source code | Zero-cost authentication forgery for any account | [T-001](#t-001) — JWT forgery |
| 🔴 | Logic | Sandboxed eval() used for user-controlled order data | Sandbox escape yields OS-level code execution | [T-008](#t-008) — RCE via B2B |
| 🟠 | Frontend | Angular DomSanitizer bypassed in 5 components | XSS in any browser that views the affected page | [T-016](#t-016) — Stored XSS, [T-018](#t-018) — Admin XSS |
| 🟠 | Data | Secrets (key, HMAC) co-located with application code | Rotation impossible without code change | [T-001](#t-001), [T-005](#t-005) — HMAC bypass |
| 🟠 | Infrastructure | 6 unauthenticated sensitive endpoints | Full reconnaissance with zero authentication | [T-011](#t-011), [T-023](#t-023), [T-024](#t-024), [T-025](#t-025), [T-026](#t-026) |

_Legend: 🔴 Critical architecture defect · 🟠 High architecture defect_

### Mitigations

#### Prioritized Mitigations

| Priority | Mitigation | Addresses | Effort |
|----------|------------|-----------|--------|
| **P1 — Immediate** | [M-001](#m-001) — Remove hardcoded RSA private key | [T-001](#t-001) — JWT forgery | Medium |
| **P1 — Immediate** | [M-002](#m-002) — Parameterize SQL queries | [T-002](#t-002) — SQLi login, [T-007](#t-007) — SQLi search | Medium |
| **P1 — Immediate** | [M-003](#m-003) — Upgrade express-jwt + enforce RS256 | [T-003](#t-003) — alg:none bypass | Low |
| **P1 — Immediate** | [M-004](#m-004) — Replace MD5 with bcrypt | [T-004](#t-004) — Weak hashing | Medium |
| **P1 — Immediate** | [M-005](#m-005) — Externalize HMAC key | [T-005](#t-005) — HMAC bypass | Low |
| **P1 — Immediate** | [M-007](#m-007) — Remove eval in B2B orders | [T-008](#t-008) — RCE | High |
| **P1 — Immediate** | [M-014](#m-014) — Remove bypassSecurityTrustHtml | [T-016](#t-016), [T-018](#t-018), [T-019](#t-019) — XSS | Medium |
| **P1 — Immediate** | [M-016](#m-016) — Disable XXE noent:true | [T-020](#t-020) — XXE | Low |

#### Follow-up Mitigations

| Priority | Mitigation | Addresses | Effort |
|----------|------------|-----------|--------|
| **P2 — This Sprint** | [M-008](#m-008) — Replace $where NoSQL query | [T-009](#t-009) — NoSQL injection | Medium |
| **P2 — This Sprint** | [M-009](#m-009) — Enforce ownership checks | [T-010](#t-010) — IDOR, [T-014](#t-014) — Review IDOR | Medium |
| **P2 — This Sprint** | [M-010](#m-010) — Auth on admin/metrics endpoints | [T-011](#t-011), [T-025](#t-025), [T-027](#t-027) | Low |
| **P2 — This Sprint** | [M-011](#m-011) — Auth on /support/logs | [T-012](#t-012), [T-026](#t-026) | Low |
| **P2 — This Sprint** | [M-015](#m-015) — Move JWT to httpOnly cookies | [T-017](#t-017) — Token in localStorage | High |
| **P2 — This Sprint** | [M-017](#m-017) — Fix ZIP path traversal | [T-021](#t-021) — File overwrite | Low |
| **P2 — This Sprint** | [M-018](#m-018) — Block SSRF in image upload | [T-022](#t-022) — SSRF | Medium |
| **P2 — This Sprint** | [M-019](#m-019) — Remove unauthenticated directory listings | [T-023](#t-023), [T-024](#t-024) — FTP/keys exposure | Low |
| **P2 — This Sprint** | [M-020](#m-020) — Re-enable auth on PUT /api/Products/:id | [T-028](#t-028) — Product tampering | Low |

### Operational Strengths

| Control | What it provides | Limitation |
|---------|-----------------|------------|
| Docker containerization (Dockerfile) | Non-root user (UID 65532); process isolation; reproducible build | No secret isolation; key material baked into image |
| express-rate-limit on password reset | Throttles brute-force of reset endpoint | Not applied to login endpoint; no account lockout |
| Helmet.js headers (noSniff + frameguard) | Prevents MIME-sniffing and clickjacking | xssFilter deliberately disabled; CSP absent |
| Morgan + rotating access logs | HTTP request audit trail available | Logs stored in-process; unauthenticated /support/logs |
| CycloneDX SBOM generation | SCA-ready bill of materials for dependency tracking | Not integrated into CI gate; outdated libs present |
| Cypress + Mocha E2E and unit tests | Regression coverage for challenge scenarios | Security-specific test cases absent for injection payloads |
| HTTPS-capable deployment | TLS termination supported in Docker deployment | Default config runs HTTP on port 3000 |

**Bottom line:** The application has a structural testing harness and deployment scaffolding, but no meaningful security controls on its critical paths — authentication, authorization, and input handling are all intentionally broken, consistent with its role as a training target.

---

## Critical Attack Chain

The diagrams below show how Critical findings combine into distinct attacker workflows. Each chain corresponds to one bullet under Worst Case Scenarios in the Management Summary. Nodes link directly to their full detail row in Section 8.1.

### Chain 1 — Unauthenticated Authentication Bypass via Hardcoded Key

This chain shows how an attacker with only internet access can forge an administrator JWT using the publicly committed private key and gain full administrative control.

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated\nattacker"]):::crit
    T1["T-001\nHardcoded RSA key\n(lib/insecurity.ts:24)"]:::crit
    T3["T-003\nalg:none bypass\n(express-jwt 0.1.3)"]:::crit
    Goal(["Admin session\nany account"]):::crit
    Start -->|"read public GitHub repo"| T1
    T1 -->|"sign JWT role=admin"| Goal
    Start -->|"craft alg:none token"| T3
    T3 -->|"token accepted"| Goal
```

**Key takeaway:** Two independent paths reach admin-level access without any credentials — the hardcoded key and the algorithm bypass are each sufficient on their own, and both are exploitable by an unauthenticated attacker in under 60 seconds.

### Chain 2 — Mass Data Exfiltration via Unauthenticated SQL Injection

This chain shows how an attacker can extract the entire user database without any prior access, then crack the MD5 hashes offline.

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated\nattacker"]):::crit
    T7["T-007\nSQLi on search\n(routes/search.ts:22)"]:::crit
    T2["T-002\nSQLi on login\n(routes/login.ts:35)"]:::crit
    T4["T-004\nMD5 hashing\n(lib/insecurity.ts:42)"]:::crit
    Goal(["All user credentials\nin plaintext"]):::crit
    Start -->|"GET /rest/products/search?q=UNION SELECT"| T7
    T7 -->|"all emails + MD5 hashes"| T4
    Start -->|"POST /rest/user/login OR 1=1--"| T2
    T2 -->|"admin session"| Goal
    T4 -->|"rainbow table crack"| Goal
```

**Key takeaway:** The combination of unauthenticated SQL injection and MD5-hashed passwords means a complete credential dump with plaintext recovery is possible in a single HTTP request followed by offline processing — no session, no account, no interaction required.

### Chain 3 — Authenticated RCE via B2B Sandbox Escape

This chain shows how a registered user (attacker with any valid account) escalates from application user to server shell.

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Registered\nuser"]):::crit
    T8["T-008\nNotevil sandbox\nescape RCE\n(routes/b2bOrder.ts:19)"]:::crit
    Goal(["OS shell\napp process privileges"]):::crit
    Start -->|"POST /b2b/v2/orders with\nprototype pollution payload"| T8
    T8 -->|"vm.runInContext escape"| Goal
    Goal -->|"erase audit logs"| Goal
```

**Key takeaway:** Any registered user can trigger remote code execution on the server with a single POST request — the only barrier is having a valid JWT, which can be obtained via SQLi ([T-002](#t-002)) or forged via [T-001](#t-001) or [T-003](#t-003).

### Quick reference — Critical findings

| ID | Title | Component | Mitigation |
|----|-------|-----------|------------|
| [T-001](#t-001) | Hardcoded RSA Private Key | Auth Service | [M-001](#m-001) — Remove from source; load from env |
| [T-002](#t-002) | SQL Injection on Login | Auth Service | [M-002](#m-002) — Parameterized queries |
| [T-003](#t-003) | JWT alg:none Bypass | Auth Service | [M-003](#m-003) — Upgrade express-jwt; enforce RS256 |
| [T-007](#t-007) | Unauthenticated SQL Injection on Search | REST API | [M-002](#m-002) — Parameterized queries |
| [T-008](#t-008) | RCE via B2B Eval Sandbox Escape | REST API | [M-007](#m-007) — Remove eval; use schema validation |

---

## 1. System Overview

OWASP Juice Shop is a deliberately vulnerable web application maintained by OWASP as a training platform for web application security. It presents itself as an online juice shop and is built as a modern full-stack application with a Node.js/Express backend serving a REST API and an Angular single-page application frontend. The intentional vulnerabilities span the OWASP Top 10 and beyond, covering SQL injection, XSS, authentication flaws, access control failures, XXE, SSRF, RCE, and many others — all real implementation defects embedded in working application code.

**Deployment context:** The application runs as a single Express process on port 3000. The SQLite database runs in-process via Sequelize. A MarsDB in-memory store (MongoDB-compatible API) serves orders and reviews. File uploads are written to the local filesystem. There is no API gateway, no WAF, no separate auth service, and no network segmentation between tiers.

**Compliance scope:** OWASP Top 10 (2021), CWE. This is a Tier 1 asset designated as an intentionally vulnerable training application maintained by the OWASP Juice Shop team.

**Context sources used:** None (no external context endpoint configured; no business-context.md found in repository).

**Overall security impression:** As intended, this application is comprehensively insecure. Every tier — authentication, authorization, data access, input handling, and infrastructure — contains severe, exploitable defects. The five Critical findings ([T-001](#t-001) through [T-003](#t-003), [T-007](#t-007), [T-008](#t-008)) each independently yield full application compromise. The architecture concentrates risk by co-locating signing keys, application logic, and data in a single process with no isolation layers. Fixes are straightforward in all cases — the attack surface is large but the mitigations are well-understood.

---

## 2. Architecture Diagrams

The following diagrams model the system architecture at two abstraction levels using the C4 model. Security-relevant components are highlighted in red. All trust boundaries are represented as subgraphs.

<!-- QA: component 'frontend-spa' has High threats (T-016, T-017, T-018, T-019) but no '%% component: frontend-spa' annotation contract marker in the Section 2 architecture diagrams. The annotator cannot annotate the Angular/Browser nodes. Add '%% component: frontend-spa' above the Angular node in the 2.3 Technology Architecture diagram and rerun annotate_architecture.py. -->

### 2.1 System Context

The Context view shows who interacts with the system, which external services it depends on, and which trust zones each actor sits in. Red boxes mark components with Critical or High threats.

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["Public Internet - untrusted"]
        User["Anonymous User\nBrowser / curl"]:::person
        Attacker["Attacker\nUnauthenticated"]:::person
    end

    subgraph APPZONE["Application Zone - port 3000"]
        %% component: rest-api
        JuiceShop["OWASP Juice Shop\nExpress 4 + Angular 20\nNode.js 24 / TypeScript\nDocker container"]:::risk
    end

    subgraph DATASTORAGE["Data Tier - in-process"]
        %% component: rest-api
        SQLite[("SQLite\nUsers, Products\nOrders via Sequelize")]:::db
        MarsDB[("MarsDB in-memory\nOrders, Reviews\nMongoDB-compat API")]:::db
        Filesystem["File System\nuploads/ ftp/\nencryptionkeys/"]:::risk
    end

    subgraph EXTERNAL["External - untrusted"]
        Google["Google OAuth\nSSO provider"]:::external
        CDN["GitHub\nPublic source code\nHardcoded private key"]:::risk
    end

    User -->|"HTTPS GET/POST port 3000"| JuiceShop
    Attacker -->|"HTTPS GET/POST all endpoints"| JuiceShop
    JuiceShop -->|"SQL queries via Sequelize ORM"| SQLite
    JuiceShop -->|"NoSQL queries MarsDB API"| MarsDB
    JuiceShop -->|"File read/write"| Filesystem
    Attacker -->|"Read hardcoded RSA key"| CDN
    User -->|"OAuth2 redirect"| Google
    Google -->|"OIDC id_token"| JuiceShop

    %% Trust Boundary Key:
    %% INTERNET->APPZONE: no API gateway, no WAF; direct TCP to Express
    %% APPZONE->DATASTORAGE: in-process calls, no network boundary
    %% APPZONE->EXTERNAL: HTTPS to Google; GitHub is public
```

**Key takeaway:** Every external request — including the attacker — reaches the Express monolith directly on port 3000 with no API gateway, no WAF, and no reverse proxy providing an additional inspection layer.

### 2.2 Container Diagram

The Container view zooms into the deployable units. The critical observation: the entire application is a single process — authentication logic, business logic, file parsing, and database access all run in the same Node.js event loop.

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    Browser["User Browser\nAngular 20 SPA\nJWT in localStorage"]:::risk

    subgraph DOCKER["Docker Container - Node 24"]
        %% component: rest-api
        Express["Express 4 HTTP Server\nserver.ts entry point\nRoutes + Middleware"]:::risk
        %% component: auth-service
        AuthLib["Auth Library\nlib/insecurity.ts\nJWT sign/verify + crypto"]:::risk
        %% component: file-upload
        FileHandlers["File Upload Handlers\nXML / ZIP / YAML / Image\nroutes/fileUpload.ts"]:::risk
        %% component: admin-panel
        AdminRoutes["Admin Routes\n/rest/admin /ftp /metrics\nno auth middleware"]:::risk
    end

    subgraph STORAGE["In-Process Storage"]
        SQLiteDB[("SQLite\nsequelize ORM\ndatabase.sqlite")]:::db
        MarsDBStore[("MarsDB\nin-memory\norders + reviews")]:::db
        LocalFS["Local Filesystem\nftp/ encryptionkeys/\nlogs/ uploads/"]:::risk
    end

    Browser -->|"HTTP REST API calls"| Express
    Browser -->|"Static assets served"| Express
    Express -->|"isAuthorized + jwtFrom(req)"| AuthLib
    Express -->|"Sequelize raw query - SQLi possible"| SQLiteDB
    Express -->|"MarsDB $where - NoSQLi possible"| MarsDBStore
    Express -->|"File parse + write"| FileHandlers
    FileHandlers -->|"libxmljs2 noent=true (XXE)"| LocalFS
    FileHandlers -->|"unzipper path traversal"| LocalFS
    AdminRoutes -->|"No auth - direct response"| Express

    %% Trust Boundary Key:
    %% Browser->Express: HTTP; no mTLS; JWT validated by express-jwt
    %% Express->SQLite: Sequelize ORM; raw query() calls bypass parameterization
    %% Express->MarsDB: $where operator allows server-side JS eval
```

**Key takeaway:** The monolith has no internal isolation — a successful RCE in the B2B route ([T-008](#t-008)) runs in the same event loop as the auth library, the database connections, and the file system handlers, with no process or memory boundary between them.

### 2.3 Technology Architecture

This diagram shows the runtime middleware stack from top to bottom. Nodes colored red carry at least one Medium-or-higher threat from the register.

```mermaid
graph TD
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef safe fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef infra fill:#2E7D32,stroke:#1B5E20,color:#fff

    subgraph BROWSER["Browser Client"]
        Angular["Angular 20 SPA\nTypeScript + Material"]:::risk
        LS["localStorage\nJWT token storage"]:::risk
    end

    subgraph EXPRESS["Express 4 Middleware Stack"]
        Helmet["Helmet.js headers\nnoSniff + frameguard\nxssFilter DISABLED"]:::risk
        CORS["cors() wildcard\nall origins allowed"]:::risk
        JWT["express-jwt 0.1.3\nRS256 + alg:none accepted"]:::risk
        Routes["Route Handlers\n60+ endpoints\npartial auth coverage"]:::risk
    end

    subgraph DATAACCESS["Data Access Layer"]
        Sequelize["Sequelize 6 ORM\nRAW SQL via query()"]:::risk
        MarsDBLib["MarsDB\n$where JS eval"]:::risk
        Libxml["libxmljs2 0.37\nnoent=true XXE"]:::risk
        Multer["multer 1.4 LTS\nfile upload parsing"]:::safe
    end

    subgraph STORAGE2["Storage"]
        SQLite2[("SQLite\nUsers, Products")]:::infra
        InMemory[("MarsDB in-memory\nOrders, Reviews")]:::infra
        FS["Local Filesystem\nftp/ encryptionkeys/"]:::risk
    end

    subgraph DOCKER2["Docker Node 24"]
        NodeJS["Node.js 24\nTypeScript runtime"]:::safe
    end

    Angular -->|"HTTP REST calls"| Helmet
    LS -->|"Authorization: Bearer JWT"| JWT
    Helmet -->|"passes through"| CORS
    CORS -->|"passes through"| JWT
    JWT -->|"req.user populated"| Routes
    Routes -->|"Sequelize.query() raw"| Sequelize
    Routes -->|"ordersCollection.find($where)"| MarsDBLib
    Routes -->|"libxml.parseXml noent=true"| Libxml
    Sequelize -->|"SQL"| SQLite2
    MarsDBLib -->|"JS eval"| InMemory
    Libxml -->|"file:// entity read"| FS
    NodeJS -->|"hosts"| EXPRESS
```

**Key takeaway:** The security-critical path — browser to JWT validation to database — has three independently exploitable breaks: the localStorage token storage, the alg:none bypass in express-jwt 0.1.3, and the raw SQL in Sequelize.query() calls.

### 2.4 Security Architecture Assessment

The assessment below evaluates structural patterns rather than individual code defects. Each pattern is rated as present, partial, or absent based on code and configuration evidence.

#### 2.4.1 Architecture Patterns

The following table evaluates which security architecture patterns are implemented. Each pattern is rated based on code and configuration evidence from the recon phase.

| Pattern | Status | Assessment |
|---------|--------|------------|
| API Gateway | ❌ Absent | No centralized gateway in front of Express. Authentication, rate limiting, and request validation must be implemented per-route, resulting in inconsistent enforcement across 60+ endpoints — some routes have no auth middleware at all. |
| BFF (Backend for Frontend) | ❌ Absent | The SPA communicates directly with the REST API with no BFF layer. JWT tokens are stored in localStorage because there is no server-side session boundary to hold an httpOnly cookie. |
| Defense-in-Depth | ❌ Absent | No WAF, no IDS, no egress filtering. The application relies entirely on per-route validation which is inconsistently applied. A single bypass at any validation point yields full compromise. |
| Separation of Concerns | ⚠️ Partial | Auth logic is centralized in `lib/insecurity.ts` but the same file contains both the signing key and the verification logic, making key isolation impossible without a code change. |
| Least Privilege | ⚠️ Partial | Docker runs as non-root (UID 65532). However, the application process can read and write any path within the container, and secrets are co-located with application code. |
| Secrets Management | ❌ Absent | Two production secrets (RSA private key, HMAC key) are hardcoded as string literals in source code. No environment variable loading, no secrets manager integration. |
| Network Segmentation | ❌ Absent | All components — web server, database, file system — run in a single process with no network separation. A successful RCE has immediate access to all tiers. |
| Secure Defaults | ❌ Absent | Multiple insecure defaults: CORS wildcard, xssFilter disabled, alg:none accepted, no CSP header, hardcoded cookie secret, unauthenticated management endpoints. |

**Assessment:** 0 of 8 patterns are fully present; 2 are partially implemented. This is by design for a training application, but it means the architecture provides zero structural defense — every compromise path is a straight line from the public internet to the data tier.

#### 2.4.2 Key Architectural Risks

The following table identifies structural design decisions that amplify or enable individual vulnerabilities. These are not code-level bugs but architecture-level defects — fixing individual threats without addressing the underlying structural risk leaves the system exposed to the same class of attack through different vectors.

| Risk | Structural Risk | Why this matters | Linked Threats |
|------|----------------|-----------------|----------------|
| 🔴 Critical | **Secrets in source code** — both the RSA private key and HMAC secret are string literals in `lib/insecurity.ts` | Any code read (GitHub access, directory traversal, log disclosure) yields the complete key material, making authentication meaningless. A correctly designed architecture would never co-locate key material with code. | [T-001](#t-001) — JWT forgery<br/>[T-005](#t-005) — HMAC bypass |
| 🔴 Critical | **No parameterized queries** — `sequelize.query()` with string interpolation used for login and search | Two different SQL injection paths exist at the most sensitive endpoints. Parameterized queries would eliminate both with a single architectural decision, but raw query() is used throughout. | [T-002](#t-002) — SQLi login<br/>[T-007](#t-007) — SQLi search |
| 🔴 Critical | **eval() in authenticated endpoint** — `vm.runInContext(safeEval(orderLinesData))` uses a sandboxed eval for user input | Any sandbox bypass escalates directly to OS-level RCE because the eval runs in the same process as the web server. An architecture that never evaluates user input eliminates this entire class of vulnerability. | [T-008](#t-008) — RCE via B2B |
| 🟠 High | **Sanitizer bypassed by design** — 5 calls to `bypassSecurityTrustHtml` in Angular components | Angular's built-in XSS protection is explicitly disabled for user-controlled content. Any stored attacker-controlled string becomes an XSS vector in any browser that views the affected page. | [T-016](#t-016) — Stored XSS<br/>[T-018](#t-018) — Admin XSS |
| 🟠 High | **No authentication on management surface** — /ftp, /encryptionkeys, /support/logs, /metrics, /rest/admin/* served without middleware | An attacker can enumerate the entire application state, download signing keys, and read access logs before ever attempting authentication. | [T-023](#t-023) — FTP listing<br/>[T-024](#t-024) — Keys exposure<br/>[T-025](#t-025) — Metrics<br/>[T-026](#t-026) — Logs |

#### 2.4.3 Secret Management

**Current state.** Two production secrets are hardcoded as string literals: the RSA private key at [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24) and the HMAC signing key at [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43). No environment variable loading or secrets manager integration exists anywhere in the codebase.

**Structural defects:**

- RSA private key literal in source code at [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24) — publicly readable on GitHub
- HMAC secret literal 'pa4qacea4VK9t9nGv7yZtwmj' at [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) — anyone with source access can pre-compute all security answer HMACs
- Cookie parser secret 'kekse' hardcoded at [server.ts:289](vscode://file/home/mrohr/juice-shop/server.ts:289)
- No startup validation that secrets are present — missing env vars would silently use undefined
- Key rotation requires a source code change and redeployment

**Impact.** An attacker with read access to the source code (public GitHub) can forge session tokens, bypass password reset, and read signed cookies without any server interaction.

**Target architecture.** Load all secrets from environment variables at startup with explicit validation: `if (!process.env.JWT_PRIVATE_KEY) throw new Error(...)`. For production, use a secrets manager (HashiCorp Vault, AWS Secrets Manager) with a 90-day rotation policy. Signing keys should never appear in version control.

**Linked threats:**

- [T-001](#t-001) — Hardcoded RSA private key
- [T-005](#t-005) — Hardcoded HMAC key for security answers
- [T-029](#t-029) — Hardcoded cookie secret

#### 2.4.4 Authentication

**Current state.** RS256 JWTs are issued on login by [lib/insecurity.ts:56](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:56) using `jwt.sign(user, privateKey, {algorithm: 'RS256'})`. Verification uses [lib/insecurity.ts:57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) via `jws.verify(token, publicKey)` without algorithm enforcement. The express-jwt version 0.1.3 is used for route protection.

**Structural defects:**

- `jws.verify()` at [lib/insecurity.ts:57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) accepts any algorithm including alg:none — no algorithm whitelist enforced
- express-jwt 0.1.3 at [package.json:38](vscode://file/home/mrohr/juice-shop/package.json:38) is approximately 8 major versions behind and has known alg:none vulnerability
- Private key hardcoded at [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24) — anyone with repo access can forge tokens offline
- JWT stored in localStorage — accessible to any XSS payload on the page
- No token revocation mechanism — compromised tokens remain valid for 6 hours
- isAuthorized() middleware not applied to all sensitive endpoints (e.g., /rest/admin/*)

**Impact.** Three independent authentication bypass paths exist: (1) forge a token offline using the hardcoded private key, (2) craft an alg:none token, or (3) bypass login via SQL injection. Any single path grants attacker-chosen identity including admin.

**Target architecture.** Delegate authentication to an external OIDC provider. The application verifies signatures via the IdP's published JWKS endpoint, enforcing RS256 algorithm explicitly with `algorithms: ['RS256']` in express-jwt v8+. Tokens are stored as httpOnly SameSite=Strict cookies to prevent XSS extraction.

```mermaid
graph TD
    subgraph CURRENT["Current State — Vulnerable"]
        LOGIN_ROUTE["routes/login.ts\nRaw SQL injection"]:::risk
        INSECURITY["lib/insecurity.ts\nHardcoded RSA key"]:::risk
        VERIFY["jws.verify()\nalg:none accepted"]:::risk
        LS2["localStorage\nJWT stored"]:::risk
    end
    subgraph TARGET["Target Architecture"]
        OIDC["External IdP\nOIDC / JWKS"]
        JWKS["JWKS endpoint\nalgorithm enforced"]
        HTTPCOOKIE["httpOnly cookie\nSameSite=Strict"]
    end
    LOGIN_ROUTE -->|"sign JWT with hardcoded key"| INSECURITY
    INSECURITY -->|"JWT in response body"| LS2
    LS2 -->|"Authorization: Bearer"| VERIFY
    OIDC -->|"id_token RS256"| JWKS
    JWKS -->|"validated user"| HTTPCOOKIE
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** The current authentication chain has three independent breaks each sufficient for full bypass; the target architecture removes all three by eliminating the hardcoded key, enforcing algorithm, and moving the token out of JavaScript-accessible storage.

**Linked threats:**

- [T-001](#t-001) — Hardcoded RSA private key
- [T-002](#t-002) — SQL injection on login
- [T-003](#t-003) — JWT alg:none bypass
- [T-017](#t-017) — JWT in localStorage

#### 2.4.5 Authorization and Access Control

**Current state.** Authorization uses the `isAuthorized()` middleware ([lib/insecurity.ts:54](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54)) which validates the JWT signature, and `isAccounting()` ([lib/insecurity.ts:156](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:156)) which additionally checks for the `accounting` role. Neither middleware verifies resource ownership — only that the user is authenticated.

**Structural defects:**

- No ownership check on basket endpoint at [routes/basket.ts:17](vscode://file/home/mrohr/juice-shop/routes/basket.ts:17) — IDOR allows cross-user data access
- Data export at [routes/dataExport.ts:26](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26) uses `req.body.UserId` instead of authenticated user's ID
- PUT /api/Products/:id has authorization middleware commented out at [server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369)
- /rest/admin/application-configuration and /rest/admin/application-version have no middleware at [server.ts:604-605](vscode://file/home/mrohr/juice-shop/server.ts:604)
- No centralized policy decision point — authorization is per-route and inconsistently applied

**Impact.** Any authenticated user can access other users' data (IDOR), modify products without admin privileges, and view the full application configuration — all without privilege escalation.

**Target architecture.** Introduce a centralized authorization middleware that enforces both role-based access control and resource ownership. Every data endpoint must compare the requested resource owner with the authenticated user's ID before responding. Admin endpoints must require an explicit `role === 'admin'` check, not just authentication.

**Linked threats:**

- [T-010](#t-010) — IDOR on basket and data export
- [T-014](#t-014) — Review ownership bypass
- [T-027](#t-027) — Authenticated users list
- [T-028](#t-028) — PUT Products without auth

#### 2.4.6 Input Validation and Output Encoding

**Current state.** Input validation is scattered across individual route handlers with no central validation middleware. Output encoding relies on Angular's built-in sanitizer, which is explicitly bypassed via `bypassSecurityTrustHtml` in five components. Sanitize-html 1.4.2 (outdated) is used for some server-side cleanup.

**Structural defects:**

- No parameterized queries — raw string interpolation in login and search routes
- `bypassSecurityTrustHtml` in 5 Angular components disables XSS protection for user-controlled content
- XML parser configured with `noent: true` — enables XXE entity expansion
- YAML parsed with `yaml.load()` instead of schema-restricted safe parsing — enables YAML bomb
- ZIP path traversal via weak `includes()` check instead of strict prefix validation
- `$where` operator passes user input directly to server-side JavaScript evaluator

**Impact.** Every major injection class — SQL, NoSQL, XSS, XXE, path traversal — has at least one confirmed exploitation path. The application surface is essentially unvalidated at the data tier.

**Target architecture.** Validate all input at the boundary using a schema library (Zod, ajv, Joi). Parameterize all database queries. Remove all `bypassSecurityTrustHtml` calls. Disable dangerous parser options. Apply defense-in-depth encoding at all output contexts.

**Linked threats:**

- [T-002](#t-002), [T-007](#t-007) — SQL injection
- [T-009](#t-009) — NoSQL injection
- [T-016](#t-016), [T-018](#t-018), [T-019](#t-019) — XSS via sanitizer bypass
- [T-020](#t-020) — XXE via noent
- [T-021](#t-021) — ZIP path traversal

#### 2.4.7 Separation and Isolation

**Current state.** The application is a monolith with all components running in a single Node.js process. Docker provides container-level isolation from the host OS. Within the container there is no process separation, no network segmentation between tiers, and no filesystem isolation between the web root, application code, and sensitive file directories.

**Structural defects:**

- Authentication library, business logic, file system access, and database connections share one event loop
- Encryption keys directory (/encryptionkeys) is inside the web root and served publicly
- FTP directory (/ftp) with sensitive files is inside the web root
- Log files (/support/logs) are inside the web root and readable via HTTP
- No separate process for file parsing (XML, ZIP, YAML) — parser crashes affect the HTTP server

**Impact.** A successful RCE ([T-008](#t-008)) gives an attacker access to all data tiers, signing keys, log files, and the ability to overwrite application code in a single exploit — because everything is co-located in one process with one filesystem context.

**Target architecture.** Move file parsing to an isolated worker process or serverless function. Remove sensitive directories (/encryptionkeys, /ftp, /support/logs) from the web root. Implement strict Content Security Policy. Use Docker network isolation between the application and storage tiers.

**Linked threats:**

- [T-008](#t-008) — RCE access to all tiers
- [T-023](#t-023), [T-024](#t-024) — Sensitive files in web root
- [T-026](#t-026) — Logs in web root

#### 2.4.8 Defense-in-Depth

**Current state.** The [Technology Architecture diagram](#23-technology-architecture) shows a single-tier defense model: if an attack bypasses route-level validation, there is no secondary control. Helmet.js provides minimal HTTP security headers (noSniff and frameguard) but the XSS filter is deliberately disabled. No CSP header is configured. No WAF, no rate limiting on the majority of endpoints.

**Structural defects:**

- No Content Security Policy — inline JavaScript executes freely
- xssFilter commented out in helmet configuration at [server.ts:187](vscode://file/home/mrohr/juice-shop/server.ts:187)
- Rate limiting applied to only 3 routes; 60+ routes have none
- No anomaly detection or behavioral alerting
- Access logs exposed ([T-026](#t-026)) — attacker can observe their own detection and adapt

**Impact.** Every attack that reaches a vulnerable route succeeds without any compensating control absorbing or detecting it. An attacker can iterate through injection payloads at full HTTP speed with no throttling.

**Target architecture.** Add a WAF or API gateway in front of the Express server as the first defense layer. Configure a strict CSP allowing only same-origin scripts. Apply rate limiting globally as a middleware default, with tighter limits on authentication endpoints. Ship logs to an immutable external system to preserve audit trails even under RCE.

**Linked threats:**

- [T-006](#t-006) — Brute-force login (no rate limit)
- [T-012](#t-012) — Log deletion under RCE
- [T-030](#t-030) — DoS via unauthenticated static endpoints

#### 2.4.9 Overall Architecture Security Rating

🔴 **Critical gaps** — the application has no meaningful security architecture. Authentication relies on secrets embedded in source code; authorization has IDOR gaps and commented-out middleware; input validation is absent on the two highest-traffic endpoints; the defense-in-depth posture is a single, easily bypassed layer. This is the expected outcome for an intentionally vulnerable training platform, but in production context every one of these findings represents an immediate, independently exploitable breach. The 21 mitigations in Section 9 address each gap with concrete, low-to-medium effort changes.

---

## 3. Attack Walkthroughs

The sequence diagrams below trace each Critical finding from initial attacker action to full exploitation. Every diagram is anchored to its T-NNN in the Threat Register (Section 8.1) and shows the current vulnerable behaviour alongside the post-mitigation flow.

### SQLi Login Bypass ([T-002](#t-002))

This sequence shows how an unauthenticated attacker bypasses the login check entirely using SQL injection on the login form, obtaining an admin session without knowing any password.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express POST /rest/user/login
    participant DB as SQLite via Sequelize

    alt Current state — T-002 SQL injection login bypass
        A->>API: POST email="' OR 1=1--" password="x"
        API->>DB: SELECT * FROM Users WHERE email='' OR 1=1-- AND password=MD5('x')
        Note over DB: SQL comment strips password check; returns first user (admin)
        DB-->>API: admin@juice-sh.op row
        API-->>A: 200 OK JWT token role=admin
        Note over A: Full admin access — no password needed
    else After M-002 — Parameterized queries
        A->>API: POST email="' OR 1=1--" password="x"
        API->>DB: SELECT * FROM Users WHERE email=? AND password=? (bound params)
        Note over DB: Literal string treated as email value; no match found
        DB-->>API: null
        API-->>A: 401 Invalid email or password
    end
```

**Key takeaway:** The fix is a single line change — replacing string interpolation with a replacements parameter in sequelize.query() — that eliminates the entire SQL injection class on this endpoint.

### Offline JWT Forgery via Hardcoded Key ([T-001](#t-001))

This sequence shows how an attacker uses the public GitHub repository to extract the hardcoded RSA private key and forge a valid admin JWT without any server interaction.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant GH as GitHub Public Repo
    participant Tool as jwt.io or node script
    participant API as Express protected route

    alt Current state — T-001 Hardcoded RSA private key
        A->>GH: Read lib/insecurity.ts line 24
        GH-->>A: RSA private key (PKCS1 format)
        A->>Tool: jwt.sign({data:{role:'admin',email:'a@b.c'}}, privateKey, {algorithm:'RS256'})
        Tool-->>A: Valid RS256 JWT token
        A->>API: GET /rest/user/authentication-details Authorization: Bearer forged-token
        Note over API: express-jwt validates signature using publicKey — matches
        API-->>A: 200 all active user sessions and tokens
    else After M-001 — Key from environment variable
        Note over GH: No key material in source code
        A->>GH: Read lib/insecurity.ts — only process.env.JWT_PRIVATE_KEY reference
        Note over A: Cannot forge token without the runtime key value
        A->>API: GET /rest/user/authentication-details with crafted token
        API-->>A: 401 Unauthorized — signature verification fails
    end
```

**Key takeaway:** Moving the private key from the source file to an environment variable removes the attack entirely — the attacker has no way to forge a valid token without accessing the running container's environment.

### RCE via B2B Eval Sandbox Escape ([T-008](#t-008))

This sequence shows how a registered user escapes the notevil sandbox and achieves arbitrary Node.js code execution on the server.

```mermaid
sequenceDiagram
    participant A as Registered User
    participant API as Express POST /b2b/v2/orders
    participant VM as vm.createContext sandbox
    participant OS as Node.js process

    alt Current state — T-008 Sandbox escape RCE
        A->>API: POST orderLinesData=Object.keys(this.__proto__)... (prototype pollution payload)
        API->>VM: vm.runInContext('safeEval(orderLinesData)', sandbox, timeout=2000)
        Note over VM: notevil sandbox escape via __proto__ manipulation
        VM->>OS: require('child_process').execSync('id')
        OS-->>VM: uid=65532 gid=0
        VM-->>API: error with leaked command output
        API-->>A: 500 error containing OS command output
        Note over A: Server shell access confirmed
    else After M-007 — JSON schema validation
        A->>API: POST orderLinesData=Object.keys(this.__proto__)...
        API->>API: ajv.validate(schema, JSON.parse(orderLinesData))
        Note over API: Schema validation rejects non-array or non-object structure
        API-->>A: 400 Invalid order data — no eval executed
    end
```

**Key takeaway:** Replacing eval() with a strict schema validator eliminates RCE entirely — the fix requires no structural changes, only removing the vm.runInContext call and adding an ajv schema check in its place.

---

## 4. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them.

Classification legend: **Restricted** — loss causes regulatory/legal consequence; **Confidential** — internal data not for public disclosure; **Internal** — operational data with limited external impact; **Public** — intentionally publicly accessible.

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| JWT RSA Private Key | Restricted | Hardcoded RSA private key in lib/insecurity.ts used to sign all session tokens | [T-001](#t-001) |
| User Credentials (email + MD5 passwords) | Confidential | All registered user emails and MD5-hashed passwords stored in SQLite | [T-002](#t-002), [T-004](#t-004), [T-007](#t-007) |
| User PII (address, card, orders) | Confidential | Payment methods, delivery addresses, and order history for all users | [T-010](#t-010), [T-009](#t-009) |
| Session Tokens (JWT) | Confidential | RS256 JWTs issued on login, stored in localStorage on the client | [T-003](#t-003), [T-017](#t-017) |
| Encryption Keys Directory | Restricted | /encryptionkeys/ served publicly over HTTP including jwt.pub and premium.key | [T-024](#t-024) |
| FTP Directory (backup files) | Internal | /ftp/ served with directory listing including acquisitions.md, package.json.bak, incident-support.kdbx | [T-023](#t-023) |
| Access Logs | Internal | HTTP access logs exposed at /support/logs without authentication | [T-026](#t-026) |
| Application Configuration | Internal | Full runtime config including OAuth client IDs, feature flags, domain settings | [T-011](#t-011) |
| Prometheus Metrics | Internal | Application performance metrics exposed unauthenticated at /metrics | [T-025](#t-025) |
| Product Catalog and Reviews | Public | Products and user reviews, directly modifiable via unauthenticated NoSQL injection | [T-009](#t-009), [T-014](#t-014) |

---

## 5. Attack Surface

All identified entry points through which an attacker can interact with the system, split by whether authentication is required.

### 5.1 Unauthenticated entry points (8)

These endpoints are reachable by any actor on the internet without credentials. They represent the highest-risk attack surface because no prior access is required.

| # | Entry Point | Protocol | Notes | Linked Threats |
|---|------------|----------|-------|----------------|
| E-001 | POST /rest/user/login | HTTP | SQL injection via raw string interpolation; no rate limiting | [T-002](#t-002), [T-006](#t-006) |
| E-002 | GET /rest/products/search | HTTP | UNION-based SQL injection via q parameter; full DB extraction | [T-007](#t-007) |
| E-003 | POST /file-upload | HTTP | Accepts XML (XXE), ZIP (path traversal), YAML bomb; no authentication | [T-020](#t-020), [T-021](#t-021), [T-013](#t-013) |
| E-004 | GET /ftp | HTTP | Directory listing; backup files including .kdbx and .bak downloadable | [T-023](#t-023) |
| E-005 | GET /encryptionkeys | HTTP | Directory listing exposes jwt.pub and premium.key | [T-024](#t-024) |
| E-006 | GET /support/logs | HTTP | Directory listing and file download of application access logs | [T-026](#t-026), [T-012](#t-012) |
| E-007 | GET /metrics | HTTP | Prometheus metrics endpoint exposing request patterns and feature flags | [T-025](#t-025) |
| E-008 | GET /rest/admin/application-configuration | HTTP | Full application config dump including OAuth client IDs | [T-011](#t-011) |

### 5.2 Authenticated entry points (2)

These endpoints require a valid JWT but can be reached by any registered user. Their security depends entirely on the integrity of the authentication layer — which has three independent bypass paths ([T-001](#t-001), [T-002](#t-002), [T-003](#t-003)).

| # | Entry Point | Protocol | Notes | Linked Threats |
|---|------------|----------|-------|----------------|
| E-009 | POST /b2b/v2/orders | HTTP | RCE via notevil sandbox escape; requires isAuthorized | [T-008](#t-008) |
| E-010 | POST /profile/image/url | HTTP | SSRF — fetches attacker-supplied URLs server-side | [T-022](#t-022) |

---

## 6. Trust Boundaries

Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|---------|------|----|-----------------------|-------------|----------------|
| 1 | Internet to Express Monolith | Public internet (any actor) | Express port 3000 | None — direct TCP connection; no API gateway, no WAF | No traffic inspection layer; authentication inconsistently applied per-route | [T-002](#t-002), [T-007](#t-007), [T-008](#t-008) |
| 2 | HTTP to SQLite via Sequelize | Express route handlers | SQLite database (in-process) | Sequelize ORM | Raw `sequelize.query()` with string interpolation bypasses parameterization | [T-002](#t-002), [T-007](#t-007) |
| 3 | HTTP to MarsDB NoSQL | Express route handlers | MarsDB in-memory store (in-process) | MarsDB query API | `$where` operator executes server-side JavaScript; user input reaches evaluator | [T-009](#t-009) |
| 4 | Browser to Angular SPA | User browser (client) | Angular application | express-jwt signature validation | JWT stored in localStorage — accessible to any executing JavaScript | [T-017](#t-017), [T-016](#t-016) |
| 5 | Server to External URLs | Express server process | External HTTP endpoints | None | `fetch(url)` with attacker-supplied URL and no IP/scheme restriction (SSRF) | [T-022](#t-022) |
| 6 | Server to File System | Express route handlers | Local filesystem | Weak path containment checks | ZIP traversal and XXE both reach the filesystem; logs and keys in web root | [T-020](#t-020), [T-021](#t-021), [T-023](#t-023) |

**Boundary 1 note:** The absence of an API gateway means that authentication, rate limiting, and input validation must be enforced individually on every route. In practice this leads to the multiple unauthenticated management endpoints identified in Section 5.1 — consistent enforcement is architecturally impossible without a central enforcement point.

**Boundary 2 note:** The Sequelize ORM supports parameterized queries via the `replacements` option, but the security-critical login and search routes use raw `sequelize.query()` with template literals. This is a per-route decision, not an ORM limitation.

---

## 7. Identified Security Controls

The following controls were identified in the codebase through static analysis. Their effectiveness is rated based on implementation completeness and known bypasses.

**Gap summary:** The most critical control gaps are: (1) no parameterized queries on the two most-trafficked unauthenticated endpoints; (2) no algorithm enforcement on JWT verification, making express-jwt's signature validation bypassable; (3) passwords hashed with MD5 rather than a password hashing function — effectively unprotected once leaked; (4) Angular's XSS protection explicitly disabled in five components; (5) five sensitive paths (FTP, keys, logs, admin config, metrics) served without any authentication middleware.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|----------------|
| IAM | JWT Authentication (express-jwt) | [lib/insecurity.ts:54](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) — expressJwt with RS256 publicKey | ⚠️ Partial | [T-003](#t-003) — alg:none accepted |
| IAM | Rate limiting on password reset | [server.ts:343](vscode://file/home/mrohr/juice-shop/server.ts:343) — express-rate-limit on /rest/user/reset-password | ⚠️ Partial | [T-006](#t-006) — login has no rate limit |
| IAM | 2FA TOTP support | [routes/2fa.ts](vscode://file/home/mrohr/juice-shop/routes/2fa.ts) — TOTP second factor on login | ✅ Adequate | — |
| Authorization | Role-based middleware (isAccounting) | [lib/insecurity.ts:156](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:156) — accounting role check | ⚠️ Partial | [T-010](#t-010) — no ownership check |
| Authorization | isAuthorized middleware | [server.ts:355–397](vscode://file/home/mrohr/juice-shop/server.ts:355) — selective route protection | ⚠️ Partial | [T-028](#t-028) — PUT /api/Products unprotected |
| Authorization | denyAll middleware | [server.ts:370](vscode://file/home/mrohr/juice-shop/server.ts:370) — blocks specific operations | ✅ Adequate | — |
| Data Protection | Password hashing | [lib/insecurity.ts:42](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:42) — crypto.createHash('md5') | 🔶 Weak | [T-004](#t-004) — MD5 not a KDF |
| Data Protection | HMAC for security answers | [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) — HMAC-SHA256 with hardcoded key | 🔶 Weak | [T-005](#t-005) — hardcoded key |
| Input Validation | sanitize-html (server-side) | [lib/insecurity.ts:62](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:62) — sanitizeHtmlLib v1.4.2 | 🔶 Weak | [T-016](#t-016) — client-side bypass |
| Input Validation | sanitizeFilename | [lib/insecurity.ts:64](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:64) — sanitize-filename | ⚠️ Partial | — |
| Input Validation | Helmet.js headers | [server.ts:185](vscode://file/home/mrohr/juice-shop/server.ts:185) — noSniff + frameguard | ⚠️ Partial | [T-016](#t-016) — xssFilter disabled |
| Input Validation | Upload size check | [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) — checkUploadSize middleware | ⚠️ Partial | [T-013](#t-013) — YAML bomb still possible |
| Audit and Logging | Morgan HTTP access logging | [server.ts:338](vscode://file/home/mrohr/juice-shop/server.ts:338) — combined format to rotating file | ⚠️ Partial | [T-026](#t-026) — logs publicly readable |
| Infrastructure | CORS | [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) — cors() without origin restriction | 🔶 Weak | [T-029](#t-029) — wildcard origin |
| Infrastructure | Docker containerization | [Dockerfile](vscode://file/home/mrohr/juice-shop/Dockerfile) — non-root user UID 65532 | ⚠️ Partial | — |
| Infrastructure | IP filter for accounting | [server.ts:430](vscode://file/home/mrohr/juice-shop/server.ts:430) — IpFilter(['123.456.789']) | ❌ Missing | Placeholder IP; filter has no effect |
| Dependency | CycloneDX SBOM generation | [package.json:sbom](vscode://file/home/mrohr/juice-shop/package.json) — cyclonedx-npm | ⚠️ Partial | — |
| Security Testing | Cypress E2E test suite | [cypress.config.ts](vscode://file/home/mrohr/juice-shop/cypress.config.ts) — challenge verification tests | ⚠️ Partial | — |
| Security Testing | Mocha server unit tests | [test/server/](vscode://file/home/mrohr/juice-shop/test/) — route-level unit tests | ⚠️ Partial | — |

---

## 8. Threat Register

The threat register lists every confirmed STRIDE finding with its evidence, current state, and the mitigation that addresses it. Threats are split into four sub-sections by severity so the reader can see at a glance what is critical and what is hardening work.

**Risk methodology:** Risk = Likelihood × Impact. Likelihood considers exploitability, attack complexity, and required privileges. Impact considers confidentiality, integrity, and availability effects on the identified assets.

| Likelihood \ Impact | Low | Medium | High | Critical |
|---|---|---|---|---|
| **High** | Low | Medium | High | Critical |
| **Medium** | Low | Medium | Medium | High |
| **Low** | Low | Low | Medium | High |

**Risk Distribution:** Critical: 5 · High: 19 · Medium: 6 · Low: 0 · **Total: 30**
**STRIDE Coverage:** Spoofing: 5 · Tampering: 5 · Repudiation: 1 · Information Disclosure: 13 · Denial of Service: 3 · Elevation of Privilege: 3

### 8.1 Critical (5)

These findings combine high exploitability with maximum impact. Every entry here is referenced by the Critical Attack Chain and is the source of P1 rollout actions in the Management Summary.

<!-- QA: T-003 has (Likelihood=Medium, Impact=Critical) which maps to High in the Risk Matrix, but the Risk cell says Critical. Mark as architectural_violation with an explicit escalation note if the Critical rating is intentional (alg:none bypass yields full auth bypass — analyst may have escalated due to architectural impact). -->
<!-- QA: T-008 has (Likelihood=Medium, Impact=Critical) which maps to High in the Risk Matrix, but the Risk cell says Critical. Mark as architectural_violation with an explicit escalation note if the Critical rating is intentional (RCE via any registered user — analyst may have escalated due to architectural impact). -->

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | Auth Service | Tampering | The RSA private key is hardcoded in source code at [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24). Anyone with read access to the repository (public GitHub) can extract this key and forge arbitrary JWT tokens with any role (admin, accounting, deluxe). Tokens signed with the hardcoded key are accepted by expressJwt as fully valid. [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | High | Critical | 🔴 Critical | RS256 algorithm used; express-jwt validates signature | [M-001](#m-001) — Remove hardcoded key |
| <a id="t-002"></a>T-002 | Auth Service | Spoofing | The login route ([routes/login.ts:35](vscode://file/home/mrohr/juice-shop/routes/login.ts:35)) constructs a raw SQL query using string interpolation. An attacker can bypass authentication using SQL injection payloads such as `' OR 1=1--` to log in as any user including admin without knowing the password. [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | High | Critical | 🔴 Critical | Password is MD5-hashed before comparison; no parameterization | [M-002](#m-002) — Parameterize SQL |
| <a id="t-003"></a>T-003 | Auth Service | Elevation of Privilege | The `jws.verify()` call in [lib/insecurity.ts:57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) does not enforce the algorithm parameter. express-jwt version 0.1.3 ([package.json](vscode://file/home/mrohr/juice-shop/package.json)) is known to accept algorithm:none JWTs. An attacker can craft a token with alg:none, strip the signature, and be accepted as any user including admin without possessing the private key. [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Medium | Critical | 🔴 Critical | RS256 specified in jwt.sign(); not enforced in jws.verify() | [M-003](#m-003) — Upgrade + enforce algorithm |
| <a id="t-007"></a>T-007 | REST API | Information Disclosure | The product search endpoint ([routes/search.ts:22](vscode://file/home/mrohr/juice-shop/routes/search.ts:22)) uses raw SQL interpolation. A UNION SELECT attack can extract the entire Users table including emails and MD5-hashed passwords, plus `sqlite_master` to retrieve the full database schema. The endpoint is unauthenticated and accepts GET requests. [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | High | Critical | 🔴 Critical | Input truncated to 200 chars; no parameterization | [M-002](#m-002) — Parameterize SQL |
| <a id="t-008"></a>T-008 | REST API | Elevation of Privilege | The B2B order endpoint ([routes/b2bOrder.ts:19](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:19)) passes user-controlled `orderLinesData` to `safeEval()` inside a `vm.createContext` sandbox. The notevil library's sandbox can be escaped via prototype pollution, achieving arbitrary Node.js code execution on the server. The endpoint requires isAuthorized but any registered user can reach it. [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Medium | Critical | 🔴 Critical | vm.createContext sandbox; 2s timeout; isAuthorized required | [M-007](#m-007) — Remove eval |

### 8.2 High (19)

High-rated threats require remediation in the current sprint or quarter. They typically gate the next release.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-004"></a>T-004 | Auth Service | Information Disclosure | Passwords are hashed with MD5 ([lib/insecurity.ts:42](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:42)). MD5 is not a password hashing function; it is fast and preimage-invertible via rainbow tables. A full database dump obtained via SQL injection (T-007) yields all user passwords in crackable form within minutes. [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | High | High | 🟠 High | Hash applied before storage; no salt | [M-004](#m-004) — Replace with bcrypt |
| <a id="t-005"></a>T-005 | Auth Service | Elevation of Privilege | The security answer is verified using HMAC-SHA256 with a hardcoded key 'pa4qacea4VK9t9nGv7yZtwmj' ([lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43)). An attacker who reads the source code can pre-compute answers for any security question, enabling password reset for any account. [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Medium | High | 🟠 High | Rate limit on reset-password endpoint; HMAC-SHA256 used | [M-005](#m-005) — Externalize HMAC key |
| <a id="t-009"></a>T-009 | REST API | Information Disclosure | The order tracking endpoint ([routes/trackOrder.ts:17](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:17)) queries MarsDB using `$where` which executes server-side JavaScript. An attacker can inject operators to enumerate all orders, leaking order data for all customers. The endpoint is unauthenticated. [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | High | High | 🟠 High | Input sanitization applied when challenge is disabled | [M-008](#m-008) — Remove $where |
| <a id="t-010"></a>T-010 | REST API | Information Disclosure | The basket endpoint GET /rest/basket/:id ([routes/basket.ts:17](vscode://file/home/mrohr/juice-shop/routes/basket.ts:17)) does not verify that the requested basket ID belongs to the authenticated user (IDOR). The dataExport endpoint ([routes/dataExport.ts:26](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26)) uses `req.body.UserId` rather than the authenticated user's ID. [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | High | High | 🟠 High | isAuthorized on basket route; no ownership check | [M-009](#m-009) — Ownership checks |
| <a id="t-011"></a>T-011 | REST API | Information Disclosure | GET /rest/admin/application-configuration ([server.ts:605](vscode://file/home/mrohr/juice-shop/server.ts:605)) is served without any authentication middleware. The response includes the full runtime config including Google OAuth client ID, email domain, and chatbot settings. [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | High | Medium | 🟠 High | None | [M-010](#m-010) — Add auth to admin endpoints |
| <a id="t-014"></a>T-014 | REST API | Tampering | The product reviews endpoint PUT /rest/products/:id/reviews allows any authenticated user to update any review regardless of authorship — no ownership check. The PATCH endpoint requires isAuthorized but the underlying handler at [routes/updateProductReviews.ts](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts) does not validate reviewer identity. [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | High | Medium | 🟠 High | isAuthorized on PATCH; no authorship check | [M-009](#m-009) — Ownership checks |
| <a id="t-016"></a>T-016 | Frontend SPA | Tampering | The search result component ([frontend/src/app/search-result/search-result.component.ts:132](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132)) calls `bypassSecurityTrustHtml` on product descriptions. A stored XSS payload injected into a product description is rendered as trusted HTML in every user's browser, enabling session theft via localStorage access. [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | High | High | 🟠 High | Angular default sanitization explicitly disabled | [M-014](#m-014) — Remove sanitizer bypass |
| <a id="t-017"></a>T-017 | Frontend SPA | Information Disclosure | JWT session tokens are stored in localStorage. Any JavaScript executing on the page — including stored XSS (T-016), third-party scripts, or malicious browser extensions — can read localStorage and exfiltrate session tokens. [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | High | High | 🟠 High | RS256 JWT; 6-hour expiry; no httpOnly cookie | [M-015](#m-015) — httpOnly cookies |
| <a id="t-018"></a>T-018 | Frontend SPA | Tampering | The administration component ([frontend/src/app/administration/administration.component.ts:60](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60)) renders user email and feedback fields via `bypassSecurityTrustHtml`. A user who registers with an XSS payload as their email will have that payload executed in the context of every admin who views the administration page. [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | High | High | 🟠 High | bypassSecurityTrustHtml explicitly used; no sanitization | [M-014](#m-014) — Remove sanitizer bypass |
| <a id="t-019"></a>T-019 | Frontend SPA | Spoofing | The last-login-ip component ([frontend/src/app/last-login-ip/last-login-ip.component.ts:39](vscode://file/home/mrohr/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.ts:39)) renders lastLoginIp via `bypassSecurityTrustHtml`. The X-Forwarded-For header is trusted and not sanitized on login. An attacker can set a spoofed IP containing an XSS payload to execute code in victim's browser. [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Medium | High | 🟠 High | bypassSecurityTrustHtml used; no IP sanitization | [M-014](#m-014) — Remove sanitizer bypass |
| <a id="t-020"></a>T-020 | File Upload | Information Disclosure | The XML upload handler ([routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)) parses XML with libxmljs2 using `noent:true`, enabling external entity resolution (XXE). An attacker can upload a crafted XML file referencing `file:///etc/passwd` or internal URLs to read arbitrary server files. [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | High | High | 🟠 High | vm sandbox around XML parse; libxmljs2 v0.37.0 | [M-016](#m-016) — Disable noent |
| <a id="t-021"></a>T-021 | File Upload | Tampering | The ZIP upload handler ([routes/fileUpload.ts:37](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:37)) extracts ZIP archives to `uploads/complaints/`. The path check uses `absolutePath.includes(path.resolve('.'))` which can be bypassed with path traversal sequences in ZIP entry names (e.g., `../../ftp/legal.md`). [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | High | High | 🟠 High | Weak path containment check; no strict prefix check | [M-017](#m-017) — Fix path traversal |
| <a id="t-022"></a>T-022 | File Upload | Spoofing | The profile image URL upload ([routes/profileImageUrlUpload.ts:23](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:23)) fetches any URL supplied by an authenticated user using server-side `fetch(url)` with no URL scheme restriction. An attacker can supply internal URLs to probe cloud metadata services (SSRF). [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | High | High | 🟠 High | Weak check for /solve/challenges/ path only | [M-018](#m-018) — Block SSRF |
| <a id="t-023"></a>T-023 | Admin Panel | Information Disclosure | The /ftp directory is served with full directory listing ([server.ts:269](vscode://file/home/mrohr/juice-shop/server.ts:269)) without authentication. It contains sensitive files including acquisitions.md, package.json.bak, and incident-support.kdbx. Null-byte injection bypasses the extension filter. [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | High | High | 🟠 High | robots.txt Disallow; extension allowlist with null-byte bypass | [M-019](#m-019) — Remove directory listing |
| <a id="t-024"></a>T-024 | Admin Panel | Information Disclosure | The /encryptionkeys directory is served with full directory listing ([server.ts:277](vscode://file/home/mrohr/juice-shop/server.ts:277)) without authentication, exposing jwt.pub and premium.key. This directly supports T-001 offline JWT forgery. [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | High | Medium | 🟠 High | None | [M-019](#m-019) — Remove directory listing |
| <a id="t-026"></a>T-026 | Admin Panel | Information Disclosure | The /support/logs directory ([server.ts:281](vscode://file/home/mrohr/juice-shop/server.ts:281)) is served with directory listing and unauthenticated file download. Access logs contain IP addresses, user emails from request bodies, and full URL paths. [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | High | Medium | 🟠 High | Morgan access logging enabled; no auth on /support/logs | [M-011](#m-011) — Protect logs endpoint |
| <a id="t-027"></a>T-027 | Admin Panel | Elevation of Privilege | The authenticated users list GET /rest/user/authentication-details returns all currently authenticated users and their tokens. An admin-level attacker with a forged token (T-001) can harvest valid session tokens for impersonation of all active users. [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Medium | High | 🟠 High | isAuthorized required; returns sensitive token data | [M-010](#m-010) — Restrict sensitive endpoints |
| <a id="t-028"></a>T-028 | Admin Panel | Tampering | PUT /api/Products/:id has its isAuthorized middleware commented out in [server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369). Any authenticated user can modify product names, descriptions, prices, and images without admin privileges. [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | High | Medium | 🟠 High | POST requires isAuthorized; PUT authorization commented out | [M-020](#m-020) — Re-enable auth on PUT |

### 8.3 Medium (6)

Medium-rated threats represent meaningful gaps with either reduced exploitability or contained impact. They should be tracked and remediated as part of normal hardening work.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-006"></a>T-006 | Auth Service | Denial of Service | No rate limiting exists on POST /rest/user/login. An attacker can brute-force account credentials at high speed. The lack of account lockout means unlimited attempts per account, amplified by weak MD5 password hashing (T-004). [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Medium | Medium | 🟡 Medium | Rate limit on reset-password only; none on login | [M-006](#m-006) — Add login rate limiting |
| <a id="t-012"></a>T-012 | REST API | Repudiation | Access logs are exposed at /support/logs without authentication ([server.ts:281](vscode://file/home/mrohr/juice-shop/server.ts:281)). An attacker can read logs to understand patterns, and a successful RCE (T-008) can erase audit trails since logs are co-located with the application. [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | Medium | Medium | 🟡 Medium | Winston + Morgan logging; log rotation enabled | [M-011](#m-011) — Protect logs and external log storage |
| <a id="t-013"></a>T-013 | REST API | Denial of Service | The YAML upload handler ([routes/fileUpload.ts:117](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:117)) passes uploaded YAML to `yaml.load()` inside a vm sandbox. A crafted YAML bomb causes exponential memory allocation before the sandbox timeout fires. [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Medium | Medium | 🟡 Medium | 2-second vm timeout; some size checking | [M-012](#m-012) — Strict upload limits |
| <a id="t-015"></a>T-015 | REST API | Spoofing | GET /redirect?to=url ([routes/redirect.ts](vscode://file/home/mrohr/juice-shop/routes/redirect.ts)) validates the target against a whitelist but the validation can be bypassed by URL parsing quirks. An attacker can craft redirect URLs pointing to phishing pages while appearing to originate from the trusted Juice Shop domain. [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | Medium | Medium | 🟡 Medium | isRedirectAllowed allowlist; bypass possible | [M-013](#m-013) — Strengthen redirect validation |
| <a id="t-025"></a>T-025 | Admin Panel | Information Disclosure | The Prometheus metrics endpoint GET /metrics ([server.ts:718](vscode://file/home/mrohr/juice-shop/server.ts:718)) is served without authentication. It exposes request counts, response times, and endpoint usage patterns that accelerate attacker reconnaissance. [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | High | Low | 🟡 Medium | None | [M-010](#m-010) — Add auth to metrics |
| <a id="t-029"></a>T-029 | Admin Panel | Spoofing | The CORS configuration applies `cors()` without origin restriction ([server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182)), allowing any origin to make cross-origin requests. Combined with the hardcoded cookie secret 'kekse' ([server.ts:289](vscode://file/home/mrohr/juice-shop/server.ts:289)), session state can be compromised from cross-origin attacker-controlled pages. [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Medium | Medium | 🟡 Medium | CORS enabled globally; no origin restriction | [M-021](#m-021) — Restrict CORS |
| <a id="t-030"></a>T-030 | Admin Panel | Denial of Service | The application serves static files and directory listings from /ftp, /encryptionkeys, /support/logs, and /.well-known without any rate limiting. An attacker can trigger high-cost operations without authentication, exhausting server resources. [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Medium | Medium | 🟡 Medium | express-rate-limit on specific routes only | [M-012](#m-012) — Global rate limiting |

### 8.4 Low (0)

_No threats at this severity level._


---

## 9. Mitigation Register

Prioritised measures to address identified threats. Each mitigation lists the threats it addresses, its rollout priority (P1–P4), and concrete implementation guidance. Within each priority group, entries are ordered by effort (lowest first), then by number of threats addressed (descending).

### P1 — Immediate

These mitigations address Critical-risk findings and should be implemented before the next release or deployment.

---

#### <a id="m-001"></a>M-001 — Remove hardcoded RSA private key; load from environment variable or secrets manager

**Addresses:** [T-001](#t-001) — Hardcoded RSA Private Key
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** The RSA private key in `lib/insecurity.ts:24` is committed to a public GitHub repository. Anyone who reads the file can forge administrator JWTs for any account. The fix requires no architectural change — only moving the key out of source code.

**How:**
1. Remove the hardcoded private key string from [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24)
2. Load the key from `process.env.JWT_PRIVATE_KEY` at startup
3. Validate the key is present on startup and throw if missing
4. Rotate the key immediately — existing tokens remain valid until 6-hour expiry
5. For production, use a secrets manager (HashiCorp Vault, AWS Secrets Manager)

```typescript
// Before (lib/insecurity.ts:24):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAK...'

// After:
const privateKey = process.env.JWT_PRIVATE_KEY
if (\!privateKey) throw new Error('JWT_PRIVATE_KEY env var not set')
```

**Verification:** Generate a token with the old key and verify it is rejected after key rotation; confirm `process.env.JWT_PRIVATE_KEY` is the signing key used in integration tests.

---

#### <a id="m-002"></a>M-002 — Parameterize all SQL queries using Sequelize bound parameters

**Addresses:** [T-002](#t-002) — SQL Injection on Login, [T-007](#t-007) — SQL Injection on Search
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Two unauthenticated SQL injection paths exist at the most-trafficked endpoints. Both use string interpolation into `sequelize.query()`. Parameterized queries eliminate both attack vectors with zero functional change.

**How:**
1. Replace string-interpolated `sequelize.query()` calls with `replacements` parameter
2. For login ([routes/login.ts:35](vscode://file/home/mrohr/juice-shop/routes/login.ts:35)): use `findOne({where: {email, password}})` or `replacements`
3. For search ([routes/search.ts:22](vscode://file/home/mrohr/juice-shop/routes/search.ts:22)): use `LIKE :criteria` with `replacements` array
4. Add integration tests for SQL injection payloads on both endpoints

```typescript
// Before (routes/login.ts:35):
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`)

// After:
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email, password: security.hash(req.body.password || '') },
    model: UserModel, plain: true }
)
```

**Verification:** Submit login with payload `' OR 1=1--` and confirm 401 response; run UNION injection against `/rest/products/search` and confirm no user data returned.

---

#### <a id="m-003"></a>M-003 — Upgrade express-jwt and enforce JWT algorithm; reject alg:none tokens

**Addresses:** [T-003](#t-003) — JWT alg:none Bypass
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** express-jwt 0.1.3 is approximately 8 major versions behind and accepts algorithm:none tokens. The fix is a package upgrade and a one-line configuration change to the `algorithms` parameter.

**How:**
1. Upgrade express-jwt from 0.1.3 to `^8.x` and jsonwebtoken from 0.4.0 to `^9.x`
2. Pass `algorithms: ['RS256']` to expressjwt configuration to reject all other algorithms
3. Replace `jws.verify()` with `jwt.verify()` with explicit algorithm enforcement
4. Add a test that sends an alg:none token and expects 401

```typescript
// Before:
export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)

// After:
import { expressjwt } from 'express-jwt'
export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: ['RS256'] })
```

**Verification:** Craft a JWT with `alg:none` and send to an isAuthorized-protected endpoint — must receive 401 Unauthorized.

---

#### <a id="m-004"></a>M-004 — Replace MD5 password hashing with bcrypt or Argon2

**Addresses:** [T-004](#t-004) — Weak MD5 Password Hashing
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** MD5-hashed passwords obtained via SQL injection ([T-007](#t-007)) crack within minutes against public rainbow tables. bcrypt's cost factor makes offline cracking computationally infeasible even with the full hash database.

**How:**
1. Add `bcrypt` dependency (`npm install bcrypt @types/bcrypt`)
2. Update `lib/insecurity.ts` `hash()` to use `bcrypt.hash()` with cost factor 12
3. Update `UserModel` to store bcrypt hashes
4. Add migration script to force re-hash on next login for existing MD5 accounts
5. Update login verification to use `bcrypt.compare()`

```typescript
// Before:
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After:
import bcrypt from 'bcrypt'
export const hashPassword = async (data: string) => bcrypt.hash(data, 12)
export const verifyPassword = async (plain: string, hash: string) => bcrypt.compare(plain, hash)
```

**Verification:** Register a new user, extract the hash from the database, confirm it starts with `$2b$` (bcrypt); confirm MD5-hashed passwords from old accounts are rejected after migration.

---

#### <a id="m-005"></a>M-005 — Load HMAC key for security answers from environment variable

**Addresses:** [T-005](#t-005) — Hardcoded HMAC Key for Security Answers
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The hardcoded HMAC key allows pre-computation of any security answer. Moving it to an environment variable eliminates the entire class of offline pre-computation.

**How:**
1. Replace hardcoded HMAC key string in [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) with `process.env.HMAC_SECRET`
2. Rotate the key on deployment (invalidates old security answers — users must re-register)
3. Consider using bcrypt for security answers since HMAC is not a KDF

```typescript
// Before:
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')...

// After:
const hmacSecret = process.env.HMAC_SECRET
if (\!hmacSecret) throw new Error('HMAC_SECRET env var not set')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacSecret)...
```

**Verification:** After key rotation, attempt password reset with a previously valid security answer — must receive 401; confirm new answers work with the new key.

---

#### <a id="m-007"></a>M-007 — Disable B2B order eval endpoint or replace with strict schema validation

**Addresses:** [T-008](#t-008) — RCE via B2B Eval Sandbox Escape
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** High

**Why:** Any `eval()` of user-controlled data is a critical architecture defect. The notevil sandbox has known escapes. Replacing the eval with a strict JSON schema validator eliminates the entire class of injection at this endpoint.

**How:**
1. Remove `vm.runInContext` and `safeEval` from [routes/b2bOrder.ts:19](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:19)
2. Define a strict JSON Schema for `orderLinesData` using ajv
3. Parse `orderLinesData` as JSON and validate against the schema
4. If the eval behavior is required for CTF purposes, isolate it in a separate container with no network access

```typescript
// Before:
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// After:
import Ajv from 'ajv'
const ajv = new Ajv()
const orderSchema = { type: 'array', items: { type: 'object',
  required: ['productId', 'quantity'],
  properties: { productId: { type: 'number' }, quantity: { type: 'number', minimum: 1 } }
}}
const data = JSON.parse(orderLinesData)
if (\!ajv.validate(orderSchema, data)) {
  return res.status(400).json({ error: 'Invalid order data' })
}
```

**Verification:** Send a payload with `Object.prototype` pollution to `/b2b/v2/orders`; confirm 400 Bad Request with schema validation error and no code execution occurs.

---

#### <a id="m-014"></a>M-014 — Remove bypassSecurityTrustHtml calls; use Angular built-in sanitization

**Addresses:** [T-016](#t-016) — Stored XSS in Search, [T-018](#t-018) — Admin XSS via User Email, [T-019](#t-019) — XSS via Last-Login IP
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Angular's DomSanitizer is explicitly bypassed in 5 components, converting Angular's XSS protection from default-secure to default-insecure. Removing the bypass calls re-enables protection with no other change required.

**How:**
1. Remove all `bypassSecurityTrustHtml()` calls from frontend components (5 occurrences)
2. Use `innerText` or `textContent` bindings instead of `innerHTML` for user-controlled content
3. For rich-text display, use DOMPurify before binding
4. Re-enable xssFilter in helmet configuration ([server.ts:187](vscode://file/home/mrohr/juice-shop/server.ts:187))
5. Files to update: `search-result.component.ts`, `administration.component.ts`, `about.component.ts`, `last-login-ip.component.ts`, `data-export.component.ts`

**Verification:** Inject `<script>alert(1)</script>` as a product description via the admin panel; confirm the payload renders as text, not as executed script in the browser.

---

#### <a id="m-016"></a>M-016 — Disable external entity resolution in XML parser to fix XXE

**Addresses:** [T-020](#t-020) — XXE in XML File Upload
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The single character change `noent: true` → `noent: false` disables external entity resolution entirely, closing the XXE attack vector.

**How:**
1. Change libxmljs2 parse options in [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) from `noent: true` to `noent: false`
2. Also set `nonet: true` to disable external DTD loading

```typescript
// Before:
libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

// After:
libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, nocdata: true })
```

**Verification:** Upload an XXE payload referencing `file:///etc/passwd`; confirm the response does not contain file contents.

---

### P2 — This Sprint

These mitigations address High-risk findings and should be completed within the current or next sprint.

---

#### <a id="m-006"></a>M-006 — Add rate limiting and account lockout to POST /rest/user/login

**Addresses:** [T-006](#t-006) — Brute-force Login Endpoint
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** The login endpoint has no throttling. An attacker can attempt unlimited credential combinations at HTTP speed. express-rate-limit is already used on the reset endpoint, so the fix is a one-line addition.

**How:**
1. Apply `express-rate-limit` middleware to `POST /rest/user/login` (10 attempts per 15 minutes per IP)
2. Implement account lockout after 5 failed attempts
3. Return 429 with `Retry-After` header on lockout
4. Log failed login attempts including IP address

```typescript
app.use('/rest/user/login', rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Too many login attempts, please try again later.' }
}))
```

**Verification:** Submit 11 login requests within 15 minutes from the same IP; confirm the 11th returns 429 with `Retry-After` header.

---

#### <a id="m-008"></a>M-008 — Replace MongoDB $where with safe equality operators

**Addresses:** [T-009](#t-009) — NoSQL Injection on Order Tracking
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** The `$where` operator executes arbitrary JavaScript server-side. Replacing it with a direct equality match on `orderId` eliminates the injection vector with no functional change.

**How:**
1. Replace `$where` server-side JS query in [routes/trackOrder.ts:17](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:17) with `{ orderId: safeId }`
2. Validate `orderId` format: alphanumeric and dash only
3. Strip non-safe characters from input before querying

```typescript
// Before:
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })

// After:
const safeId = id.replace(/[^\w-]/g, '')
db.ordersCollection.find({ orderId: safeId })
```

**Verification:** Submit a `$where` injection payload via `/rest/track-order/:id`; confirm only the exact order matching the provided ID is returned.

---

#### <a id="m-009"></a>M-009 — Enforce ownership checks on basket, data export, and review endpoints

**Addresses:** [T-010](#t-010) — IDOR on Basket and Data Export, [T-014](#t-014) — Review Ownership Bypass
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** The missing ownership checks are the same defect in three places. The fix pattern is identical for all three: compare the requested resource's owner ID with the authenticated user's ID.

**How:**
1. In [routes/basket.ts:17](vscode://file/home/mrohr/juice-shop/routes/basket.ts:17), compare `basket.UserId` with `user.data.id` before returning data
2. In [routes/dataExport.ts:26](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26), use `loggedInUser.data.id` instead of `req.body.UserId`
3. In review update routes, verify the review's author matches the authenticated user
4. Return 403 Forbidden when ownership check fails

```typescript
// routes/basket.ts — add ownership check after finding basket:
const user = security.authenticatedUsers.from(req)
if (basket && basket.UserId \!== user?.data?.id) {
  return res.status(403).json({ error: 'Access denied' })
}
```

**Verification:** Log in as User A, request User B's basket ID — must return 403; confirm data export only returns the authenticated user's own data.

---

#### <a id="m-010"></a>M-010 — Add authentication to admin configuration, metrics, and sensitive API endpoints

**Addresses:** [T-011](#t-011) — Unauthenticated Admin Config, [T-025](#t-025) — Unauthenticated Prometheus Metrics, [T-027](#t-027) — Authenticated Users List Exposure
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Adding `security.isAuthorized()` middleware to three routes in `server.ts` addresses all three findings. The middleware already exists and is applied elsewhere.

**How:**
1. Add `security.isAuthorized()` to `/rest/admin/application-configuration` and `/rest/admin/application-version`
2. Add authentication to `/metrics` endpoint or restrict to monitoring infrastructure via network policy
3. Restrict `/rest/user/authentication-details` to admin role only or remove entirely

**Verification:** Send unauthenticated GET to `/rest/admin/application-configuration`; confirm 401 response.

---

#### <a id="m-011"></a>M-011 — Protect /support/logs with authentication and implement log integrity controls

**Addresses:** [T-012](#t-012) — Log Deletion via RCE, [T-026](#t-026) — Unauthenticated Log Access
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Both findings are addressed by the same change: add `isAuthorized()` to the `/support/logs` routes and move log shipping to an external immutable store.

**How:**
1. Add `security.isAuthorized()` and admin role check to `/support/logs` routes in [server.ts:281](vscode://file/home/mrohr/juice-shop/server.ts:281)
2. Avoid logging sensitive data (JWT tokens, passwords) in access logs
3. For production, ship logs to append-only external storage (CloudWatch, Loki) outside the application process

**Verification:** Send unauthenticated GET `/support/logs`; confirm 401 response; confirm sensitive data absent from log content.

---

#### <a id="m-015"></a>M-015 — Move JWT tokens from localStorage to httpOnly cookies

**Addresses:** [T-017](#t-017) — JWT Stored in localStorage
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** High

**Why:** localStorage tokens are readable by any JavaScript on the page. An httpOnly cookie is immune to XSS-based token theft because JavaScript cannot access it at all.

**How:**
1. Set the JWT as an `httpOnly`, `Secure`, `SameSite=Strict` cookie on the login response
2. Remove `localStorage.setItem()` calls for token storage in the Angular application
3. Update HTTP interceptor to use `withCredentials` for authenticated requests
4. Add CSRF token for state-changing requests (SameSite=Strict provides baseline protection)

**Verification:** Log in, open browser DevTools > Application > localStorage — confirm no JWT visible; confirm token is in `Set-Cookie` header with `httpOnly` and `Secure` flags.

---

#### <a id="m-017"></a>M-017 — Fix ZIP path traversal using strict base-directory prefix check

**Addresses:** [T-021](#t-021) — ZIP Path Traversal File Overwrite
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The `includes()` check can be bypassed by any path that contains the base directory string as a substring. A `startsWith()` check on the normalized path is the correct fix.

**How:**
1. Replace `absolutePath.includes(path.resolve('.'))` with `absolutePath.startsWith(uploadDir + path.sep)` in [routes/fileUpload.ts:47](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:47)
2. Normalize the extracted file path before comparison

```typescript
// Before:
if (absolutePath.includes(path.resolve('.'))) { entry.pipe(...) }

// After:
const uploadDir = path.resolve('uploads/complaints/')
if (absolutePath.startsWith(uploadDir + path.sep)) {
  entry.pipe(fs.createWriteStream(absolutePath))
} else {
  entry.autodrain()
}
```

**Verification:** Upload a ZIP containing an entry with path `../../ftp/test.txt`; confirm the file is not written to `/ftp/`.

---

#### <a id="m-018"></a>M-018 — Restrict SSRF in profile image URL upload with scheme and IP allowlisting

**Addresses:** [T-022](#t-022) — SSRF via Profile Image URL
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** The server-side `fetch(url)` call with an attacker-supplied URL and no restrictions enables probing of internal services. Validating the URL's scheme and blocking private IP ranges eliminates SSRF.

**How:**
1. Parse the supplied URL and validate: only http/https schemes allowed
2. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, ::1, localhost)
3. Enforce a short timeout (3 seconds) and limit redirect-following
4. Validate `Content-Type` of response is an image before saving

```typescript
const BLOCKED = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)/
const parsed = new URL(url)
if (\!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid URL scheme')
if (BLOCKED.test(parsed.hostname) || parsed.hostname === 'localhost') throw new Error('SSRF blocked')
```

**Verification:** Supply `http://169.254.169.254/latest/meta-data/` as image URL; confirm request is blocked with 400.

---

#### <a id="m-019"></a>M-019 — Remove unauthenticated directory listings from /ftp, /encryptionkeys, /support/logs

**Addresses:** [T-023](#t-023) — FTP Directory Listing, [T-024](#t-024) — Encryption Keys Exposure
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Three directories containing sensitive files are browsable without authentication. Adding `isAuthorized()` before `serveIndex()` and moving key files out of the web root addresses both findings.

**How:**
1. Remove or restrict `serve-index` middleware for `/ftp`, `/encryptionkeys`, `/support/logs` in [server.ts:269-283](vscode://file/home/mrohr/juice-shop/server.ts:269)
2. Move `encryptionkeys/` directory outside the web root
3. Add `isAuthorized()` middleware before static file serving on sensitive paths
4. Remove backup files (`.bak`, `.kdbx`) from the FTP directory or protect with auth

**Verification:** Send unauthenticated GET `/ftp`; confirm 401 or 404; confirm `/encryptionkeys` is not browsable.

---

#### <a id="m-020"></a>M-020 — Re-enable isAuthorized and admin-role check on PUT /api/Products/:id

**Addresses:** [T-028](#t-028) — Product Tampering via Uncommented Authorization
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The authorization middleware is present in a commented-out line. Uncommenting it and adding an admin role check is a one-line fix.

**How:**
1. Uncomment and restore `security.isAuthorized()` on `app.put('/api/Products/:id', ...)` in [server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369)
2. Add an admin-role check so only `role === 'admin'` users can modify products

```typescript
// Before (server.ts:369 — commented out):
// app.put('/api/Products/:id', security.isAuthorized())

// After:
app.put('/api/Products/:id', security.isAuthorized(), security.isAdmin())
```

**Verification:** Log in as a regular user and attempt `PUT /api/Products/1` with modified name; confirm 403 response.

---

### P3 — Next Quarter

These mitigations address Medium-risk findings and should be planned for the next roadmap cycle.

---

#### <a id="m-012"></a>M-012 — Validate and limit upload file sizes; implement DoS protections on file endpoints

**Addresses:** [T-013](#t-013) — YAML Bomb DoS, [T-030](#t-030) — DoS via Unauthenticated Static Endpoints
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** Both DoS vectors require a size/rate control layer that does not exist on file parsing and static file endpoints. A global rate limit and strict size enforcement addresses both.

**How:**
1. Enforce strict upload size limits via multer `limits` option (1 MB maximum)
2. Use `yaml.safeLoad()` with schema restrictions instead of `yaml.load()`
3. Add rate limiting to `/file-upload` and static file serving endpoints globally

**Verification:** Upload a YAML bomb with deeply nested anchors; confirm server rejects with 413 before parsing begins.

---

#### <a id="m-013"></a>M-013 — Strengthen open-redirect allowlist with exact URL parsing and hostname matching

**Addresses:** [T-015](#t-015) — Open Redirect Allowlist Bypass
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** The current `startsWith()` check on the raw URL string is bypassable. Parsing the URL and checking the exact origin string closes the bypass.

**How:**
1. Parse the destination URL using the `URL` constructor and compare `origin` and `pathname` strictly
2. Reject URLs where the hostname differs from an explicit allowlist of exact hostnames

```typescript
// Before: utils.startsWith(toUrl, allowedUrl) — bypassable
// After:
const allowed = ['https://explorer.dash.org', 'https://blockchain.info', 'https://etherscan.io']
const parsed = new URL(toUrl)
if (\!allowed.includes(parsed.origin)) return res.status(406).send('Redirect not allowed')
```

**Verification:** Attempt bypass with `https://evil.com?to=https://etherscan.io` — confirm 406 response.

---

#### <a id="m-021"></a>M-021 — Restrict CORS to known origins and replace hardcoded cookie secret

**Addresses:** [T-029](#t-029) — Wildcard CORS and Hardcoded Cookie Secret
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** Wildcard CORS allows any origin to make authenticated requests. Replacing the hardcoded cookie secret prevents cookie forgery. Both are one-line fixes.

**How:**
1. Replace `cors()` with `cors({ origin: ['https://juice-sh.op'] })` in [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182)
2. Replace hardcoded cookie parser secret 'kekse' with `process.env.COOKIE_SECRET` in [server.ts:289](vscode://file/home/mrohr/juice-shop/server.ts:289)
3. Add `SameSite=Strict` to session cookies

**Verification:** Send a cross-origin preflight request from an unlisted origin; confirm 403 response in CORS preflight.

---

## 10. Out of Scope

Areas deliberately excluded from this assessment, including accepted risks and items requiring separate analysis.

- **CTF challenge mechanics** — all `challengeUtils.solveIf()` calls and the challenge trigger/verification system are intentional by design and excluded from threat analysis
- **Intentional vulnerabilities as features** — all vulnerabilities that are part of the Juice Shop training mission are documented here for awareness but are not remediated in production practice
- **Third-party dependencies not in critical paths** — dependency CVEs for libraries not directly invoked in security-sensitive code paths
- **OAuth2 / Google Login flow** — Google OAuth client ID is configured at the frontend level only; the server-side OIDC flow was not analyzed
- **Web3 / NFT minting features** — contractExploitListener, walletNFTVerify, and nftMintListener were not analyzed; they involve external smart contracts
- **CI/CD pipeline** — no GitHub Actions workflow files were found in the repository; CI/CD security is not assessed
- **Monitoring infrastructure** — Prometheus scrape configuration, Grafana dashboards, and alerting rules are outside scope
- **Container orchestration** — Kubernetes manifests and Helm charts are not present in this repository

---

## Appendix: Run Statistics

| | |
|---|---|
| **Analysis Duration** | 46 min 39 s |
| **Assessment Date** | 2026-04-14 |
| **Mode** | full |
| **Plugin Version** | 0.9.0-beta |
| **Analysis Version** | 1 |
| **Orchestrator Model** | claude-sonnet-4-6 |
| **Agent Models** | all agents: claude-sonnet-4-6 |
| **Baseline SHA** | n/a (initial run) |
| **Current SHA** | cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f |
| **Branch** | master |
| **Components Analyzed** | 5 |
| **Threats Identified** | 30 (Critical: 5 · High: 19 · Medium: 6 · Low: 0) |
| **Mitigations Generated** | 21 |

### Per-Phase Duration Breakdown

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Context Resolution | Cache hit (skipped) |
| Phase 2 | Reconnaissance — inline scan | Completed |
| Phase 3 | Architecture Modeling (Moderate complexity — 4 diagrams) | Completed |
| Phase 4 | Attack Walkthroughs (3 Critical findings) | Completed |
| Phase 5 | Asset Identification (10 assets) | Completed |
| Phase 6 | Attack Surface Mapping (10 entry points, 8 unauthenticated) | Completed |
| Phase 7 | Trust Boundary Analysis (6 boundaries) | Completed |
| Phase 8 | Security Controls Catalog (19 controls assessed) | Completed |
| Phase 9 | STRIDE Threat Enumeration (5 components, 30 threats) | Completed |
| Phase 10 | Scan Synthesis (0 SCA — WITH_SCA=false) | Completed |
| Phase 11 | Finalization | Completed |

### Token Consumption

| | |
|---|---|
| Input | 16 |
| Output | 4,648 |
| Cache Write | 97,432 |
| Cache Read | 190,006 |
| **Total** | **292,102** |

### Cost Estimate

| | sonnet-4-6 |
|---|---|
| With prompt caching | ~$0.4921 (estimated) |
| Without prompt caching | ~$0.93 (estimated) |
| Cache savings | 47.2% |

> Billing: subscription (estimated)

### Agent Roster

| Agent | Model | Role | Phases |
|-------|-------|------|--------|
| threat-analyst | claude-sonnet-4-6 | Orchestrator | 1–11 |
| stride-analyzer | claude-sonnet-4-6 | STRIDE analysis (inline) | 9 (5 components) |
