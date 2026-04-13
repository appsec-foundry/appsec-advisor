# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-13T06:50:00Z |
| Analysis Duration | 2 min 46 s |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Agent Models | all agents: claude-sonnet-4-6 |
| Context Sources | None |
| Mode | full (--full rebuild) |
| Changelog | v2 (2026-04-13) — see Changelog section |

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Technology Architecture](#22-technology-architecture)
   - [2.3 Security Architecture Assessment](#23-security-architecture-assessment)
3. [Assets](#3-assets)
4. [Attack Surface](#4-attack-surface)
   - [4.1 Unauthenticated Entry Points (12)](#41-unauthenticated-entry-points-12)
   - [4.2 Authenticated Entry Points (8)](#42-authenticated-entry-points-8)
5. [Trust Boundaries](#5-trust-boundaries)
6. [Identified Security Controls](#6-identified-security-controls)
7. [Threat Register](#7-threat-register)
   - [7.1 Critical (4)](#71-critical-4)
   - [7.2 High (8)](#72-high-8)
   - [7.3 Medium (8)](#73-medium-8)
   - [7.4 Low (3)](#74-low-3)
8. [Attack Walkthroughs](#8-attack-walkthroughs)
   - [8.1 T-001 SQL Injection — Auth Bypass and DB Exfiltration](#81-t-001--sql-injection--auth-bypass-and-db-exfiltration)
   - [8.2 T-002 Hardcoded JWT Key — Admin Token Forgery](#82-t-002--hardcoded-jwt-key--admin-token-forgery)
   - [8.3 T-004 XXE — Unauthenticated File Disclosure](#83-t-004--xxe--unauthenticated-file-disclosure)
9. [Mitigation Register](#9-mitigation-register)
10. [Out of Scope](#10-out-of-scope)
11. [Changelog](#11-changelog)
[Appendix: Run Statistics](#appendix-run-statistics)

---

<\!-- QA: ## Management Summary section is missing — required section per threat model spec; add a Management Summary with Verdict, Top Risks, Worst Case Scenarios, Architecture Assessment, Follow-up Actions, and Operational Strengths sub-sections -->

## 1. System Overview

OWASP Juice Shop (v19.2.1) is an intentionally vulnerable web application used worldwide for security training, CTF competitions, and as a target for automated security tool testing. It is maintained by Bjoern Kimminich under the OWASP umbrella and hosted publicly at [github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop).

**What it does:** Juice Shop simulates a realistic e-commerce application (fake juice store) with user accounts, a product catalogue, basket and checkout, reviews, a B2B ordering interface, a chatbot, and an admin panel. All OWASP Top Ten 2021 vulnerability categories are deliberately implemented, plus many additional flaws, making it an exhaustive training platform.

**Architecture:** The application is a Node.js/Express monolith (port 3000) serving an Angular 20 SPA as compiled static files. Persistence is split between SQLite (via Sequelize ORM) for relational data and MarsDB (an in-process MongoDB-like engine) for product reviews and orders. There is no API gateway, no reverse proxy, no WAF, and no BFF pattern — the SPA communicates directly with the Express REST API.

**Complexity tier:** Moderate. Multiple distinct layers exist (SPA frontend, REST API, auth sub-system, admin panel, file upload service), but all run within a single Node.js process with shared in-memory state.

**Users:** Security trainees, penetration testers, CTF participants, security tool developers, and security course instructors. The application is intentionally deployed in vulnerable configurations.

**Deployment:** Available as a Docker image (`bkimminich/juice-shop`), Heroku one-click deploy, and direct Node.js execution. The Dockerfile uses a distroless Node 24 base image.

**Compliance scope:** OWASP Top Ten 2021 (intentionally covers all categories). No PCI-DSS, SOC 2, or HIPAA controls are implemented.

**Overall security impression:** As designed, this application exhibits critical, confirmed, and exploitable security vulnerabilities across every STRIDE category. The most severe are: a hardcoded RSA private key for JWT signing committed in plaintext to the public repository ([T-002](#t-002)), SQL injection in the login endpoint ([T-001](#t-001)), XXE with entity expansion enabled in the XML file upload ([T-004](#t-004)), and RCE via a JavaScript sandbox escape in the B2B order endpoint ([T-003](#t-003)). These four vulnerabilities together enable full system compromise by an unauthenticated attacker. This report documents all 23 identified threats and 19 mitigations as a reference for security training and tool development.

---

## 2. Architecture Diagrams

The following diagrams model the system at the Context and Technology levels using C4 conventions. Security-relevant components are highlighted. Because DIAGRAM_DEPTH is set to `minimal` for this quick assessment, only the Context and Technology Architecture diagrams are produced.

### 2.1 System Context

The Context view shows who interacts with Juice Shop, which external services it depends on, and which trust zones each actor occupies. Red-bordered boxes mark components that expose attack surface to unauthenticated users.

```mermaid
graph TD
    subgraph Internet["Public Internet — untrusted"]
        Trainee["Security Trainee\nCTF Participant\nPentester"]
        Attacker["Attacker\nUnauthenticated"]
    end

    subgraph AppTier["Application Tier — port 3000"]
        %% component: rest-api
        JuiceShop["OWASP Juice Shop v19.2.1\nNode.js 24 + Express 4\nAngular 20 SPA\nSQLite + MarsDB"]:::risk
    end

    subgraph DataTier["Data Tier — in-process"]
        %% component: auth-service
        SQLite["SQLite DB\nSequelize ORM\nUsers / Orders / Cards"]:::db
        MarsDB["MarsDB\nIn-process NoSQL\nReviews / Orders"]:::db
    end

    subgraph External["External Services"]
        Prometheus["Prometheus\nMetrics scrape\nGET /metrics"]:::external
        Swagger["Swagger UI\nAPI docs\nGET /api-docs"]:::external
    end

    Trainee -->|"HTTPS port 3000\nBrowser or CLI"| JuiceShop
    Attacker -->|"HTTP port 3000\nUnauthenticated"| JuiceShop
    JuiceShop -->|"Sequelize ORM\nSQLite file"| SQLite
    JuiceShop -->|"MarsDB in-process\nNoSQL API"| MarsDB
    Prometheus -->|"GET /metrics\nunauthenticated"| JuiceShop
    Swagger -->|"GET /api-docs\nno auth"| JuiceShop

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    class Trainee,Attacker person
    class JuiceShop risk
    class SQLite,MarsDB db
    class Prometheus,Swagger external

%% Trust Boundary Key:
%% Public Internet → App Tier: No WAF, no API gateway, no TLS termination proxy. Express middleware is the only control layer.
%% App Tier → Data Tier: In-process — no network hop, no credential isolation, no encryption at rest.
```

**Key takeaway:** Every external request — including an unauthenticated attacker — reaches the Express monolith directly on port 3000 with no API gateway, no WAF, and no TLS-terminating proxy in front of it.

### 2.2 Technology Architecture

This diagram shows the full runtime middleware stack from browser to database, top to bottom. Nodes in red carry at least one Medium-or-higher threat from the register.

```mermaid
graph TB
    subgraph Browser["Browser — Angular 20 SPA"]
        SPA["Angular 20 SPA\nTypeScript\nMaterial UI\nJWT in localStorage"]:::risk
    end

    subgraph Express["Node.js 24 — Express 4 Monolith"]
        MW["Middleware Layer\ncors() wildcard\nhelmet partial\nmorgan logging\nbody-parser"]:::risk
        Auth["Auth Middleware\nexpress-jwt RS256\ninsecurity.ts\nMD5 passwords"]:::risk
        Routes["Route Handlers\n60+ routes/*.ts\nSQL raw queries\nNoSQL $where"]:::risk
        FileUp["File Upload\nmulter memory\nXXE libxmljs2\nZip Slip\nsafeEval RCE"]:::risk
    end

    subgraph Data["Data Tier — in-process"]
        SQLiteDB["SQLite\nSequelize ORM\nno encryption"]:::db
        MarsDBDB["MarsDB\nin-process NoSQL\n$where injection"]:::db
        FTPDir["Static Files\n/ftp/ /encryptionkeys/\n/support/logs/\nunauthenticated"]:::risk
    end

    SPA -->|"REST / HTTP\nBearer JWT\nno SameSite"| MW
    MW -->|"next()"| Auth
    Auth -->|"next() or 401"| Routes
    Auth -->|"next()"| FileUp
    Routes -->|"sequelize.query\nraw SQL"| SQLiteDB
    Routes -->|"MarsDB $where\nNoSQL"| MarsDBDB
    FileUp -->|"multer\nfile write"| FTPDir

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** The entire request path from browser to database contains confirmed injection sinks at every layer — SQL in the route handlers, NoSQL $where in MarsDB queries, and JavaScript eval in the file upload handler — with no parameterization or sanitization at any boundary.

### 2.3 Security Architecture Assessment

The assessment below evaluates structural patterns rather than individual code defects. Each pattern is rated present, partial, or absent based on evidence from the codebase.

#### 2.3.1 Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | Absent | Direct Express exposure on port 3000; no proxy, no gateway |
| BFF (Backend-for-Frontend) | Absent | SPA communicates directly with REST API; tokens in localStorage |
| Defense-in-depth | Absent | Single process; no layers between attacker and data tier |
| Separation of concerns | Partial | Routes, models, and auth in separate files; logic mixes in routes |
| Least-privilege | Absent | No role enforcement on most admin endpoints; wildcard CORS |
| Secrets management | Absent | JWT private key hardcoded in source; HMAC secret in source |
| Network segmentation | Absent | SQLite/MarsDB in-process; no network boundary to data tier |
| Secure defaults | Absent | MD5 passwords, noent:true XXE, wildcard CORS, no CSP |

#### 2.3.2 Key Architectural Risks

| # | Structural Risk | Impact if Exploited | Linked Threats |
|---|-----------------|---------------------|----------------|
| 1 | Single-process monolith with no isolation between auth, data, and file handling | Lateral movement from any component compromise to full system | [T-001](#t-001) through [T-004](#t-004) |
| 2 | In-process database with raw query construction throughout all route handlers | SQL/NoSQL injection at any route yields full DB read/write | [T-001](#t-001), [T-009](#t-009), [T-010](#t-010) |
| 3 | Secrets (JWT private key, HMAC key) committed in plaintext to public repository | Attacker forges any identity without network interaction | [T-002](#t-002) |
| 4 | No transport security configuration (no TLS, no HSTS, no CSP) | XSS payload execution, token theft, MitM credential harvest | [T-007](#t-007), [T-013](#t-013), [T-020](#t-020) |
| 5 | Client-side-only authorization for admin operations | Any authenticated user accesses admin data | [T-008](#t-008), [T-016](#t-016) |

#### 2.3.3 Secret Management

**Current state:** The RSA private key used for JWT signing is hardcoded inline at `lib/insecurity.ts:23`. The HMAC secret used for security answer validation is hardcoded at `lib/insecurity.ts:44`. Both are committed to the public GitHub repository and have been since the project's inception.

**Structural defects:** No runtime secret injection mechanism exists. There is no use of `process.env` for any sensitive value in the auth layer. The application starts without error if these values are absent because they are never absent — they are compile-time constants.

**Impact:** Any attacker who reads the public source code can forge a valid admin JWT for any user ID without sending a single request to the server, or compute a valid HMAC security answer for any user.

**Target architecture:** Move private key to `process.env.JWT_PRIVATE_KEY`, fail fast on startup if absent, rotate the key pair, and invalidate all existing sessions.

**Linked threats:** [T-002](#t-002), [T-015](#t-015)

#### 2.3.4 Authentication

**Current state:** JWT RS256 tokens issued after login via `lib/insecurity.ts:56`. Tokens validated with `expressJwt` middleware applied selectively per route. 2FA (TOTP) implemented in `routes/2fa.ts` and optional per user.

**Structural defects:** The private key for signing is hardcoded (see §2.3.3). Password verification uses unsalted MD5 (`lib/insecurity.ts:43`), making any credential database dump instantly reversible. The in-memory `authenticatedUsers.tokenMap` is the only revocation mechanism; it is lost on server restart.

**Impact:** Authentication can be completely bypassed either by forging a JWT with the published private key or by cracking an MD5-hashed password from any DB dump.

**Target architecture:** Environment-injected RSA key pair; Argon2id password hashing with per-user salt; server-side token revocation table in persistent storage.

**Linked threats:** [T-002](#t-002), [T-005](#t-005), [T-015](#t-015)

```mermaid
graph TB
    subgraph Login["Login Flow"]
        Req["POST /rest/user/login\nemail + password"]
        SQLQuery["sequelize.query\nraw SQL — T-001"]:::risk
        MD5Check["MD5 hash check\nno salt — T-005"]:::risk
        JWTSign["jwt.sign\nhardcoded key — T-002"]:::risk
        Token["JWT RS256 token\n6h expiry\nlocalStorage — T-020"]:::risk
    end

    Req -->|"string concat"| SQLQuery
    SQLQuery -->|"user row"| MD5Check
    MD5Check -->|"match"| JWTSign
    JWTSign -->|"response"| Token

    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** Every step in the authentication chain has a confirmed vulnerability — the SQL query is injectable, the password check uses crackable MD5, and the signing key is publicly known.

#### 2.3.5 Authorization and Access Control

**Current state:** `security.isAuthorized()` (JWT presence check) is applied to most authenticated routes. `security.isAccounting()` and `security.isDeluxe()` exist for special roles. Admin-level routes use only client-side `AdminGuard`.

**Structural defects:** No `isAdmin()` function exists for server-side admin enforcement. The admin panel backend routes (`/rest/admin/*`, `GET /api/Users`) are protected by `isAuthorized()` but not an admin role check, so any JWT holder can reach them.

**Impact:** Any authenticated regular customer can access all admin data and functionality that the frontend sends to the admin panel.

**Linked threats:** [T-008](#t-008), [T-016](#t-016), [T-010](#t-010)

#### 2.3.6 Input Validation and Output Encoding

**Current state:** `sanitize-html` library available in `lib/insecurity.ts:60` but not applied at REST API boundaries. `sanitize-filename` applied in some file upload paths. Angular's DomSanitizer bypassed in 8+ frontend components via `bypassSecurityTrustHtml`. No parameterized query usage.

**Structural defects:** Input validation is opt-in rather than the default. Most route handlers pass user input directly to SQL strings or NoSQL `$where` clauses. The frontend actively circumvents Angular's output encoding.

**Impact:** SQL injection, NoSQL injection, and stored/reflected XSS are all exploitable in the current build.

**Linked threats:** [T-001](#t-001), [T-007](#t-007), [T-009](#t-009), [T-013](#t-013)

#### 2.3.7 Separation and Isolation

**Current state:** All components run in a single Node.js process. SQLite database is an on-disk file accessible to the process. MarsDB is fully in-memory. No containerization within the application boundary.

**Structural defects:** A compromise of any route handler gives the attacker access to the entire database and file system with the privileges of the Node.js process. There is no sandbox between the file upload handler and the rest of the application.

**Linked threats:** [T-003](#t-003), [T-004](#t-004), [T-012](#t-012)

#### 2.3.8 Defense-in-Depth

**Current state:** Helmet applies `noSniff` and `frameguard`. Morgan logs access. Express-rate-limit is applied only to the password reset and 2FA endpoints. No WAF, no IDS, no anomaly detection.

**Structural defects:** The application has a single defensive layer (Express middleware). If that layer is bypassed (SQL injection, JWT forgery, etc.), there are no compensating controls. No alerting, no circuit breakers, no canary detection.

**Linked threats:** [T-001](#t-001), [T-002](#t-002), [T-017](#t-017)

#### 2.3.9 Overall Architecture Security Rating

🔴 **Critical gaps** — The application has confirmed critical vulnerabilities in every major security domain: authentication (hardcoded key, MD5 passwords), injection (SQL, NoSQL, XXE, RCE), access control (missing server-side admin checks, client-side-only authorization), and transport security (no CSP, no HSTS, wildcard CORS). These are intentional by design for training purposes, but represent a complete failure of every architectural security pattern. No production deployment of this codebase should occur without addressing the P1 mitigations in Section 9.

---

## 3. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them.

**Classification legend:** Restricted — highest sensitivity, breach has regulatory or severe business impact | Confidential — internal use, breach has significant impact | Internal — operational data, limited external impact | Public — intentionally public.

| Asset | Classification | Description | Linked Threats |
|-------|----------------|-------------|----------------|
| User Credentials (email + MD5 password) | Restricted | SQLite Users table; MD5-hashed passwords trivially reversible via rainbow tables | [T-001](#t-001), [T-005](#t-005) |
| JWT Private Key | Restricted | Hardcoded RSA private key in [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23); anyone can forge any JWT | [T-002](#t-002) |
| JWT Session Tokens | Confidential | RS256 tokens stored in Angular localStorage; 6-hour lifetime | [T-020](#t-020), [T-007](#t-007) |
| Payment Card Data | Restricted | Cards table in SQLite; no PCI-DSS controls in place | [T-001](#t-001), [T-011](#t-011) |
| Order and Purchase History | Confidential | MarsDB ordersCollection; NoSQL injection risk | [T-009](#t-009) |
| Product Reviews | Internal | MarsDB reviewsCollection; NoSQL injection and XSS risk | [T-009](#t-009), [T-007](#t-007) |
| Encryption Keys Directory | Restricted | [/encryptionkeys/](vscode://file/home/mrohr/juice-shop/encryptionkeys) served unauthenticated; contains jwt.pub, premium.key | [T-006](#t-006) |
| Access Logs | Internal | /support/logs/ served unauthenticated; may contain credentials in URL parameters | [T-006](#t-006), [T-018](#t-018) |
| FTP Directory | Internal | /ftp/ directory listing unauthenticated; contains backup files | [T-006](#t-006) |
| Prometheus Metrics | Internal | /metrics unauthenticated; reveals route names and usage patterns | [T-019](#t-019) |
| Application Configuration | Internal | /rest/admin/application-configuration unauthenticated | [T-008](#t-008) |
| SQLite Database File | Restricted | Contains all user data, orders, challenge state; unencrypted on disk | [T-001](#t-001) |

---

## 4. Attack Surface

All identified entry points through which an attacker can interact with the system, split by whether authentication is required.

### 4.1 Unauthenticated Entry Points (12)

An unauthenticated attacker has access to 12 entry points, four of which contain critical or high-severity vulnerabilities exploitable with no prior account.

| # | Entry Point | Protocol | Key Risk | Linked Threats |
|---|-------------|----------|----------|----------------|
| 1 | POST /rest/user/login | HTTP REST | SQL injection; no rate limit | [T-001](#t-001), [T-017](#t-017) |
| 2 | GET /rest/products/search?q= | HTTP REST | SQL injection via q parameter | [T-001](#t-001) |
| 3 | POST /file-upload | HTTP multipart | XXE; Zip Slip; YAML deserialization | [T-004](#t-004), [T-014](#t-014) |
| 4 | POST /rest/user/reset-password | HTTP REST | Weak security questions; rate limit 100/5min | [T-015](#t-015) |
| 5 | GET /ftp/* | HTTP static | Unauthenticated directory listing and file download | [T-006](#t-006) |
| 6 | GET /encryptionkeys/* | HTTP static | JWT public key and premium.key downloadable | [T-006](#t-006) |
| 7 | GET /support/logs/* | HTTP static | Unauthenticated log file access | [T-006](#t-006), [T-018](#t-018) |
| 8 | GET /metrics | HTTP | Prometheus metrics unauthenticated | [T-019](#t-019) |
| 9 | GET /rest/admin/application-version | HTTP REST | Admin endpoint, no auth | [T-008](#t-008), [T-022](#t-022) |
| 10 | GET /rest/admin/application-configuration | HTTP REST | Full app config, no auth | [T-008](#t-008) |
| 11 | GET /rest/track-order/:id | HTTP REST | NoSQL $where injection | [T-009](#t-009) |
| 12 | POST /api/Users | HTTP REST | User registration; mass assignment of role | [T-010](#t-010) |

### 4.2 Authenticated Entry Points (8)

These entry points require a valid JWT. An attacker who obtains any account (including via [T-001](#t-001) SQL injection or [T-002](#t-002) JWT forgery) can reach all of them.

| # | Entry Point | Protocol | Key Risk | Linked Threats |
|---|-------------|----------|----------|----------------|
| 1 | GET /rest/user/change-password?new=&repeat= | HTTP REST | Password in URL; no current password required | [T-018](#t-018) |
| 2 | POST /profile/image/url | HTTP REST | SSRF via arbitrary URL fetch | [T-012](#t-012) |
| 3 | PATCH /rest/products/reviews | HTTP REST | NoSQL injection and IDOR | [T-009](#t-009) |
| 4 | GET /rest/basket/:id | HTTP REST | IDOR — no ownership check on integer basket ID | [T-011](#t-011) |
| 5 | POST /b2b/v2/orders | HTTP REST | RCE via safeEval sandbox escape | [T-003](#t-003), [T-021](#t-021) |
| 6 | POST /profile/image/file | HTTP multipart | Profile image upload | — |
| 7 | GET /api/Users | HTTP REST | Full user list with masked passwords | [T-008](#t-008) |
| 8 | GET /rest/user/authentication-details | HTTP REST | Lists all active session tokens | [T-008](#t-008) |

---

## 5. Trust Boundaries

Trust boundaries mark transitions between different security zones. Weaknesses at these boundaries are primary sources of risk in this application.

The overall trust model is broken at every boundary: the Internet-to-Express boundary has no gateway layer; the unauthenticated-to-authenticated boundary relies on a forgeable JWT signed with a public key; the authenticated-to-admin boundary is enforced only client-side; and the application-to-data boundary uses raw query strings throughout.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|--------------|----------------|
| 1 | Internet to Express | Public Internet | Express middleware | None — direct TCP on port 3000 | No WAF, no API gateway, no TLS proxy | [T-001](#t-001), [T-004](#t-004), [T-006](#t-006) |
| 2 | Unauthenticated to Authenticated | Anonymous HTTP | JWT-protected routes | `security.isAuthorized()` / `express-jwt` | JWT key hardcoded; MD5 passwords; no brute-force protection on login | [T-002](#t-002), [T-005](#t-005), [T-017](#t-017) |
| 3 | Authenticated User to Admin | Regular JWT | Admin operations | Client-side `AdminGuard` in Angular only | No server-side admin role check; any JWT passes `isAuthorized()` | [T-008](#t-008), [T-016](#t-016) |
| 4 | Application to Data Tier | Express route handlers | SQLite + MarsDB | In-process function calls | Raw SQL string concatenation; NoSQL `$where` string interpolation | [T-001](#t-001), [T-009](#t-009), [T-010](#t-010) |

---

## 6. Identified Security Controls

This section catalogues all security controls found in the codebase, rated by their actual effectiveness.

**Gap summary:** The five most critical control gaps are: (1) Password storage uses unsalted MD5 — effectively no protection against credential cracking on any DB dump. (2) Content Security Policy is entirely absent — XSS payloads execute without restriction and can steal localStorage JWTs. (3) CORS is configured to allow all origins — any website can make credentialed requests to the API. (4) No rate limiting on the login endpoint — credential stuffing and brute force are unconstrained. (5) Server-side admin role enforcement is absent — any authenticated user can reach admin-only data through the API.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|----------------|
| IAM | JWT RS256 token authentication | [lib/insecurity.ts:54](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) — expressJwt validates RS256 | 🔶 Weak | [T-002](#t-002) |
| IAM | Two-Factor Authentication (TOTP) | [routes/2fa.ts](vscode://file/home/mrohr/juice-shop/routes/2fa.ts) — otplib.authenticator.check() | ⚠️ Partial | — |
| Authorization | Route-level isAuthorized() middleware | [server.ts:355-398](vscode://file/home/mrohr/juice-shop/server.ts:355) — applied to most routes | 🔶 Weak | [T-008](#t-008), [T-016](#t-016) |
| Authorization | Role-based access control | [lib/insecurity.ts:144-176](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:144) — isAccounting(), isDeluxe() | 🔶 Weak | [T-016](#t-016) |
| Authorization | Client-side route guards | [frontend/src/app/app.guard.ts](vscode://file/home/mrohr/juice-shop/frontend/src/app/app.guard.ts) — AdminGuard, AccountingGuard | ❌ Missing | [T-008](#t-008), [T-016](#t-016) |
| Data Protection | Password hashing | [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) — MD5, no salt | ❌ Missing | [T-005](#t-005) |
| Data Protection | Sensitive data encryption at rest | Not implemented — SQLite unencrypted | ❌ Missing | [T-001](#t-001) |
| Input Validation | HTML sanitization | [lib/insecurity.ts:60](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:60) — sanitize-html available but not at API boundaries | 🔶 Weak | [T-007](#t-007), [T-013](#t-013) |
| Input Validation | File type validation | [server.ts:309](vscode://file/home/mrohr/juice-shop/server.ts:309) — checkFileType middleware | ⚠️ Partial | [T-004](#t-004), [T-014](#t-014) |
| Input Validation | Filename sanitization | [lib/insecurity.ts:62](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:62) — sanitize-filename for some paths | ⚠️ Partial | [T-014](#t-014) |
| Audit and Logging | HTTP access logging | [server.ts:338](vscode://file/home/mrohr/juice-shop/server.ts:338) — morgan('combined') with rotating file | ✅ Adequate | [T-018](#t-018) (amplifies) |
| Audit and Logging | Application event logging | [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) — winston logger | ✅ Adequate | — |
| Infrastructure | X-Content-Type-Options | [server.ts:185](vscode://file/home/mrohr/juice-shop/server.ts:185) — helmet.noSniff() | ✅ Adequate | — |
| Infrastructure | X-Frame-Options | [server.ts:186](vscode://file/home/mrohr/juice-shop/server.ts:186) — helmet.frameguard() | ✅ Adequate | — |
| Infrastructure | Content Security Policy | helmet.contentSecurityPolicy() not called | ❌ Missing | [T-007](#t-007), [T-013](#t-013), [T-020](#t-020) |
| Infrastructure | HSTS | helmet.hsts() not called | ❌ Missing | — |
| Infrastructure | CORS policy | [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) — cors() with no options (wildcard) | ❌ Missing | [T-023](#t-023) |
| Infrastructure | Rate limiting | [server.ts:343-345](vscode://file/home/mrohr/juice-shop/server.ts:343) — only on /reset-password and /rest/2fa/* | 🔶 Weak | [T-017](#t-017) |
| Dependency | SBOM generation | [Dockerfile](vscode://file/home/mrohr/juice-shop/Dockerfile) — CycloneDX via @cyclonedx/cyclonedx-npm | ⚠️ Partial | — |
| Security Testing | SAST CodeQL | .github/workflows/codeql-analysis.yml | ✅ Adequate | — |
| Security Testing | DAST OWASP ZAP | .github/workflows/zap_scan.yml | ✅ Adequate | — |

---

## 7. Threat Register

This section enumerates all identified threats using the STRIDE methodology, organized by risk level. Each threat cites specific file and line evidence from the codebase.

**Risk methodology:** Risk = Likelihood × Impact. Likelihood is based on exploitability (public PoC, common tooling, skill required). Impact is based on confidentiality, integrity, and availability consequences.

**Risk Distribution:**

| Risk Level | Count |
|------------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 8 |
| 🟡 Medium | 8 |
| 🟢 Low | 3 |
| **Total** | **23** |

**STRIDE Coverage:**

| Category | Count |
|----------|-------|
| Spoofing | 5 |
| Tampering | 5 |
| Repudiation | 1 |
| Information Disclosure | 7 |
| Denial of Service | 3 |
| Elevation of Privilege | 2 |

### 7.1 Critical (4)

These four threats are individually sufficient to compromise the entire system. All are exploitable with public knowledge and standard tooling.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | rest-api | Tampering | SQL Injection in login and search — raw string concatenation at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) and [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) allows unauthenticated authentication bypass and full database exfiltration via UNION injection. CWE-89. | High | Critical | 🔴 Critical | None | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | auth-service | Spoofing | Hardcoded JWT private key at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) in public repository allows offline forging of admin tokens for any user without server interaction. CWE-321. | High | Critical | 🔴 Critical | RS256 validation against hardcoded public key | [M-002](#m-002) |
| <a id="t-003"></a>T-003 | file-upload-service | Elevation of Privilege | RCE via safeEval/notevil sandbox escape at [routes/b2bOrder.ts:24](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:24) — authenticated B2B customer can achieve arbitrary server-side code execution by crafting orderLinesData. CWE-94. | Medium | Critical | 🔴 Critical | notevil sandbox + vm.createContext; 2s timeout | [M-003](#m-003) |
| <a id="t-004"></a>T-004 | file-upload-service | Elevation of Privilege | XXE via libxmljs2 with noent:true at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) — unauthenticated attacker can read arbitrary local files including private keys via external entity injection. CWE-611. | High | Critical | 🔴 Critical | 100 KB upload size limit | [M-004](#m-004) |

### 7.2 High (8)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-005"></a>T-005 | auth-service | Spoofing | Unsalted MD5 password hashing at [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) — any database dump yields instantly crackable credentials via rainbow tables. CWE-916. | High | High | 🟠 High | None | [M-005](#m-005) |
| <a id="t-006"></a>T-006 | rest-api | Information Disclosure | Unauthenticated file system exposure via /ftp/, /encryptionkeys/, /support/logs/ serving backup files, JWT keys, and access logs to any internet user. CWE-548. | High | High | 🟠 High | robots.txt advisory only | [M-006](#m-006) |
| <a id="t-007"></a>T-007 | frontend-spa | Spoofing | Stored XSS via bypassSecurityTrustHtml in 8+ Angular components including feedback comments and admin user emails — with no CSP, XSS steals JWT from localStorage. CWE-79. | High | High | 🟠 High | No CSP; sanitize-html not applied in frontend | [M-007](#m-007) |
| <a id="t-008"></a>T-008 | admin-panel | Information Disclosure | Unauthenticated admin API endpoints GET /rest/admin/application-version and GET /rest/admin/application-configuration at [server.ts:604-605](vscode://file/home/mrohr/juice-shop/server.ts:604) have no isAuthorized() middleware. CWE-306. | High | High | 🟠 High | None | [M-008](#m-008) |
| <a id="t-009"></a>T-009 | rest-api | Tampering | NoSQL injection via MarsDB $where operator at [routes/trackOrder.ts:18](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:18) — JavaScript injection retrieves all orders from other users. CWE-943. | High | High | 🟠 High | String truncation to 60 chars when challenge is enabled | [M-009](#m-009) |
| <a id="t-010"></a>T-010 | rest-api | Tampering | Mass assignment of role field at POST /api/Users — user registering with role:admin in request body is created with admin privileges; no field-level whitelist enforced. CWE-915. | High | High | 🟠 High | verify.registerAdminChallenge() detects but does not block | [M-010](#m-010) |
| <a id="t-011"></a>T-011 | rest-api | Tampering | IDOR on basket retrieval at [routes/basket.ts](vscode://file/home/mrohr/juice-shop/routes/basket.ts) — no ownership check allows accessing any user's basket by enumerating integer basket IDs. CWE-639. | High | Medium | 🟠 High | JWT authentication required | [M-011](#m-011) |
| <a id="t-012"></a>T-012 | file-upload-service | Information Disclosure | SSRF via profile image URL at [routes/profileImageUrlUpload.ts:24](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:24) — authenticated attacker causes server to fetch internal metadata endpoints or internal services. CWE-918. | Medium | High | 🟠 High | JWT auth required; error fallback saves URL directly | [M-012](#m-012) |

### 7.3 Medium (8)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-013"></a>T-013 | frontend-spa | Spoofing | Reflected XSS at search-result.component — bypassSecurityTrustHtml on URL query parameter executes in victim browser via crafted link; no CSP prevents payload execution. CWE-79. | Medium | High | 🟡 Medium | No CSP | [M-007](#m-007) |
| <a id="t-014"></a>T-014 | file-upload-service | Tampering | Zip Slip at [routes/fileUpload.ts:41-45](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:41) — path traversal in ZIP archive entry.path can write files outside uploads/complaints/ directory. CWE-22. | Medium | High | 🟡 Medium | absolutePath.includes() check — bypassable with symlinks | [M-004](#m-004) |
| <a id="t-015"></a>T-015 | auth-service | Spoofing | Weak security questions for password reset — questions answerable from public OSINT (birth city, sibling name); rate limit of 100/5min is far too permissive. CWE-521. | Medium | High | 🟡 Medium | Rate limit: 100 req/5 min | [M-013](#m-013) |
| <a id="t-016"></a>T-016 | admin-panel | Elevation of Privilege | Client-side authorization bypass — AdminGuard only protects Angular navigation; any authenticated user can call admin API endpoints directly. CWE-284. | Medium | High | 🟡 Medium | AdminGuard client-side Angular route guard | [M-008](#m-008) |
| <a id="t-017"></a>T-017 | rest-api | Denial of Service | Brute force on login endpoint POST /rest/user/login with no rate limiting — enables high-speed credential stuffing amplified by instant MD5 cracking. CWE-307. | High | Medium | 🟡 Medium | None | [M-014](#m-014) |
| <a id="t-018"></a>T-018 | auth-service | Repudiation | Sensitive data in URL via GET /rest/user/change-password — passwords exposed in server access logs, browser history, and referrer headers. CWE-598. | High | Medium | 🟡 Medium | morgan access logging (amplifies exposure) | [M-015](#m-015) |
| <a id="t-019"></a>T-019 | rest-api | Information Disclosure | Prometheus metrics at GET /metrics unauthenticated — reveals route names, request counts, and usage patterns enabling targeted reconnaissance. CWE-200. | High | Low | 🟡 Medium | None | [M-016](#m-016) |
| <a id="t-020"></a>T-020 | frontend-spa | Information Disclosure | JWT stored in localStorage — accessible to any JavaScript on the same origin including XSS payloads, enabling token theft and session hijacking. CWE-922. | High | Medium | 🟡 Medium | JWT has 6-hour expiry | [M-007](#m-007), [M-017](#m-017) |
| <a id="t-021"></a>T-021 | rest-api | Denial of Service | Event loop saturation via unbounded JavaScript evaluation in safeEval/vm.runInContext — CPU-intensive payloads can saturate the single-threaded Node.js event loop. CWE-400. | Medium | Medium | 🟡 Medium | 2s timeout on safeEval; 200-char limit on search | [M-018](#m-018) |

### 7.4 Low (3)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-022"></a>T-022 | rest-api | Information Disclosure | Application version disclosure at GET /rest/admin/application-version — version string enables CVE cross-referencing. CWE-200. | Low | Low | 🟢 Low | None | [M-008](#m-008) |
| <a id="t-023"></a>T-023 | admin-panel | Information Disclosure | Wildcard CORS at [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) — cors() with no options allows any arbitrary origin to read API responses. CWE-942. | Low | Medium | 🟢 Low | None | [M-019](#m-019) |

---

## 8. Attack Walkthroughs

The sequence diagrams below trace each Critical finding from initial attacker action through full exploitation. Each diagram is anchored to its T-NNN entry in the Threat Register and shows current vulnerable behaviour.

### 8.1 [T-001](#t-001) — SQL Injection — Auth Bypass and DB Exfiltration

**[T-001](#t-001) · SQL Injection in Login.** Unauthenticated attacker, REST API component. This walkthrough shows how a single crafted email parameter bypasses authentication entirely and yields an admin JWT, or alternatively dumps the full user database via UNION injection.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant E as Express POST /rest/user/login
    participant Q as sequelize.query() raw SQL
    participant DB as SQLite Users table

    A->>E: POST /rest/user/login email="' OR 1=1--"
    E->>Q: SELECT * FROM Users WHERE email='' OR 1=1--' AND password=... AND deletedAt IS NULL
    Q->>DB: Execute — WHERE clause bypassed by tautology
    DB-->>Q: First user row returned (admin)
    Q-->>E: authenticatedUser = admin record
    E-->>A: 200 OK — JWT token for admin user

    Note over A,DB: Alternative: UNION exfiltration
    A->>E: POST login email="' UNION SELECT null,null,null,email,password,null,null,null,null,null,null FROM Users--"
    E->>Q: Raw UNION query executed
    Q->>DB: Returns all user rows
    DB-->>Q: All emails and MD5 hashes
    Q-->>E: Error response leaks data in some cases
```

**Key takeaway:** The single-quote in the email field is sufficient to bypass the entire authentication check or exfiltrate all user credentials with no brute force required.

### 8.2 [T-002](#t-002) — Hardcoded JWT Key — Admin Token Forgery

**[T-002](#t-002) · Hardcoded JWT Private Key.** Unauthenticated attacker (offline). This walkthrough shows how the public source code is the only resource an attacker needs to forge a valid admin JWT.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant GH as GitHub repo public source
    participant local as Attacker local machine
    participant E as Express isAuthorized()
    participant API as Admin API endpoint

    A->>GH: Read lib/insecurity.ts line 23
    GH-->>A: RSA private key (full PEM, 1024-bit)
    A->>local: jwt.sign({data:{id:1,role:'admin'}}, privateKey, {algorithm:'RS256'})
    local-->>A: Forged JWT — valid RS256 signature
    A->>E: GET /rest/admin/application-configuration Authorization: Bearer forgedJWT
    E->>E: expressJwt verifies against hardcoded public key — PASSES
    E->>API: next() — proceeds to handler
    API-->>A: Full application configuration
```

**Key takeaway:** No network interaction with the target server is required before the attacker possesses a valid admin JWT — the private key in the public repository is the vulnerability.

### 8.3 [T-004](#t-004) — XXE — Unauthenticated File Disclosure

**[T-004](#t-004) · XXE in XML File Upload.** Unauthenticated attacker, File Upload Service component. This walkthrough shows how a single malformed XML file discloses the RSA private key from disk.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant FU as POST /file-upload
    participant LX as libxmljs2 parseXml noent:true
    participant FS as File System

    A->>FU: POST /file-upload multipart XML with DOCTYPE external entity
    Note over A,FU: XML payload defines entity file=file:///home/juice-shop/lib/insecurity.ts
    FU->>LX: libxml.parseXml(data, {noent: true})
    LX->>FS: Reads referenced file path from entity
    FS-->>LX: Returns file contents (private key or /etc/passwd)
    LX-->>FU: Expanded XML string includes file contents
    FU-->>A: 410 response body contains trunc(xmlString,400) — file contents in error message
```

**Key takeaway:** The noent:true flag in the libxmljs2 call at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) is the single-character change (true to false) that closes this vulnerability entirely.

---

## 9. Mitigation Register

Prioritised measures to address identified threats. Each mitigation lists the threats it addresses, its rollout priority (P1–P4) and concrete implementation guidance. Mitigations are grouped by rollout priority, lowest-effort first within each group.

### P1 — Immediate

These four mitigations address Critical-risk vulnerabilities that are exploitable today by an unauthenticated attacker. Implement before the next public exposure of this instance.

---

#### <a id="m-001"></a>M-001 — Parameterize All Database Queries

**Addresses:** [T-001](#t-001) (SQL Injection — Critical)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** Raw string concatenation in `sequelize.query()` at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) and [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) allows full SQL injection. Switching to ORM model methods eliminates the vulnerability structurally.

**How:**
1. Replace raw `sequelize.query()` string interpolation in [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) with `UserModel.findOne({ where: { email, password } })`
2. Replace raw query in [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) with `ProductModel.findAll({ where: { [Op.or]: [...] } })`
3. Audit all `routes/` for remaining raw query string concatenation

```typescript
// Before (vulnerable):
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`
)

// After (safe):
UserModel.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password ?? ''),
    deletedAt: null
  }
})
```

**Verification:** Send `' OR 1=1--` as email to POST /rest/user/login — expect 401 not a JWT.

---

#### <a id="m-002"></a>M-002 — Remove Hardcoded JWT Private Key

**Addresses:** [T-002](#t-002) (Hardcoded JWT Key — Critical)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** The RSA private key at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) is committed to the public repository. Any person who has read the source code can forge a valid admin JWT without interacting with the server.

**How:**
1. Replace hardcoded private key string at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) with `process.env.JWT_PRIVATE_KEY`
2. Generate new RSA key pair and rotate all existing sessions
3. Set `JWT_PRIVATE_KEY` in deployment secrets manager

```typescript
// Before (vulnerable):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAI...'

// After (safe):
const privateKey = process.env.JWT_PRIVATE_KEY
  ?? (() => { throw new Error('JWT_PRIVATE_KEY must be set') })()
```

**Verification:** Start server without `JWT_PRIVATE_KEY` — expect startup error. A JWT signed with the old key must return 401.

---

#### <a id="m-003"></a>M-003 — Remove safeEval and Replace with Schema Validation

**Addresses:** [T-003](#t-003) (RCE via safeEval — Critical)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** The `notevil`/`safeEval` sandbox at [routes/b2bOrder.ts:24](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:24) is known to be escapable via prototype pollution. JavaScript sandboxing is not a reliable security boundary. Schema validation of the expected JSON structure is both safer and simpler.

**How:**
1. Remove `notevil`/`safeEval` usage from [routes/b2bOrder.ts:24](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:24)
2. Replace with Joi schema validation of the `orderLinesData` JSON structure
3. Remove `notevil` dependency from `package.json`

```typescript
// Before (vulnerable):
const sandbox = { safeEval, orderLinesData }
vm.createContext(sandbox)
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// After (safe):
const { error, value } = orderLineSchema.validate(JSON.parse(orderLinesData))
if (error) return next(new Error(`Invalid order data: ${error.message}`))
```

**Verification:** POST `{"orderLinesData":"process.exit(1)"}` — server must remain running and return a validation error.

---

#### <a id="m-004"></a>M-004 — Disable XXE and Fix Zip Slip

**Addresses:** [T-004](#t-004) (XXE — Critical), [T-014](#t-014) (Zip Slip — Medium)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** The `noent: true` flag in the libxmljs2 call at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) instructs the parser to resolve all external entities, which is the definition of XXE. A single flag change disables it. The Zip Slip uses `includes()` which is bypassable; `path.normalize()` with a strict prefix check is the correct fix.

**How:**
1. Change `noent: true` to `noent: false` in [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)
2. Replace the `includes()` path check with `path.normalize()` + `startsWith(safeBase + path.sep)` for ZIP extraction

```typescript
// Before (vulnerable XXE):
libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

// After (safe):
libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })

// Before (vulnerable Zip Slip):
if (absolutePath.includes(path.resolve('.'))) { entry.pipe(fs.createWriteStream(...)) }

// After (safe):
const safeBase = path.resolve('uploads/complaints') + path.sep
if (absolutePath.startsWith(safeBase)) { entry.pipe(fs.createWriteStream(...)) }
```

**Verification:** Upload XML with external entity DOCTYPE referencing `/etc/passwd` — expect literal text in the response, not file contents.

---

### P2 — This Sprint

These mitigations address High-risk vulnerabilities that are exploitable with standard tooling and minimal skill. Implement within the current development sprint.

---

#### <a id="m-005"></a>M-005 — Replace MD5 with Argon2id for Password Storage

**Addresses:** [T-005](#t-005) (MD5 Passwords — High)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** MD5 without salt maps any common password to a known hash value (rainbow table). Argon2id with a per-user salt requires computation proportional to the attacker's hardware budget.

**How:**
1. Install `argon2` package
2. Replace `crypto.createHash('md5')` in [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) with `argon2.hash()`
3. Add migration: on login detect MD5 hash by `/^[a-f0-9]{32}$/`, verify, re-hash with Argon2

```typescript
// Before (vulnerable):
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After (safe):
export const hash = async (data: string) =>
  argon2.hash(data, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3 })
```

**Verification:** Register a user; query `Users.password` directly — expect `$argon2id$` prefix, not 32-char hex.

---

#### <a id="m-006"></a>M-006 — Require Authentication on Sensitive File Directories

**Addresses:** [T-006](#t-006) (Unauthenticated File Exposure — High)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The `/ftp/`, `/encryptionkeys/`, and `/support/logs/` directories are served without any authentication check, exposing backup files, encryption keys, and access logs to the public internet.

**How:**
1. Add `security.isAuthorized()` before the `/ftp/*` static serving in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Add `security.isAuthorized()` before `/encryptionkeys/*` in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
3. Add `security.isAuthorized()` before `/support/logs/*` in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)

```typescript
// Before (vulnerable):
app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))

// After (safe):
app.use('/ftp', security.isAuthorized(), serveIndexMiddleware, serveIndex('ftp', { icons: true }))
```

**Verification:** `GET /ftp/acquisitions.md` without JWT — expect 401. With valid JWT — expect 200.

---

#### <a id="m-007"></a>M-007 — Remove bypassSecurityTrustHtml and Deploy CSP

**Addresses:** [T-007](#t-007) (Stored XSS — High), [T-013](#t-013) (Reflected XSS — Medium), [T-020](#t-020) (JWT in localStorage — Medium)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** High

**Why:** `bypassSecurityTrustHtml()` actively disables Angular's built-in XSS protection. Without a CSP, any successful XSS payload can access localStorage and steal the JWT token. Both mitigations together create defence-in-depth.

**How:**
1. Remove all `bypassSecurityTrustHtml()` calls in `frontend/src/app/` (8+ files) and allow Angular to sanitize `[innerHTML]` bindings automatically
2. Add `helmet.contentSecurityPolicy()` with strict directives in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)

```typescript
// Add to server.ts middleware stack:
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"], // adjust as needed
    objectSrc: ["'none'"],
    baseUri: ["'self'"]
  }
}))
```

**Verification:** Store `<script>alert(1)</script>` as a feedback comment — it must not execute. Check for `Content-Security-Policy` header in any response.

---

#### <a id="m-008"></a>M-008 — Add Server-Side Admin Role Check on Admin API Endpoints

**Addresses:** [T-008](#t-008) (Unauthenticated Admin Endpoints — High), [T-016](#t-016) (Client-side Auth Bypass — Medium), [T-022](#t-022) (Version Disclosure — Low)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The admin panel backend routes have no server-side admin role check. `isAuthorized()` only verifies that a JWT is valid, not that the token belongs to an admin user.

**How:**
1. Add `isAdmin()` middleware to [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) checking `JWT role === 'admin'`
2. Apply `security.isAuthorized()` and `security.isAdmin()` to GET `/rest/admin/*` in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
3. Verify `GET /api/Users` and `GET /rest/user/authentication-details` also enforce admin role

```typescript
// Add to lib/insecurity.ts:
export const isAdmin = () => (req: Request, res: Response, next: NextFunction) => {
  const decoded = verify(jwtFrom(req)) && decode(jwtFrom(req))
  decoded?.data?.role === roles.admin ? next() : res.status(403).json({ error: 'Forbidden' })
}

// Apply in server.ts:
app.get('/rest/admin/application-configuration', security.isAuthorized(), security.isAdmin(), retrieveAppConfiguration())
```

**Verification:** `GET /rest/admin/application-configuration` without JWT — expect 401. Customer JWT — 403. Admin JWT — 200.

---

#### <a id="m-009"></a>M-009 — Remove $where JavaScript Injection from MarsDB Queries

**Addresses:** [T-009](#t-009) (NoSQL Injection — High)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The `$where` JavaScript operator in MarsDB evaluates arbitrary JavaScript on every document in the collection. Replacing it with an equality query removes the injection surface entirely.

**How:**
1. Replace the `$where` string interpolation in [routes/trackOrder.ts:18](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:18) with an equality query `{ orderId: id }`
2. Audit all `data/mongodb.ts` usages for remaining `$where` operator usage

```typescript
// Before (vulnerable):
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })

// After (safe):
db.ordersCollection.find({ orderId: String(id).replace(/[^\w-]/g, '') })
```

**Verification:** `GET /rest/track-order/1' || '1'=='1` — expect empty result, not all orders.

---

#### <a id="m-010"></a>M-010 — Block Mass Assignment of Privileged Fields at Registration

**Addresses:** [T-010](#t-010) (Mass Assignment — High)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The `finale-rest` auto-generated API endpoint for `POST /api/Users` passes the full request body to Sequelize without any field allowlist, enabling any client to set any model field including `role`.

**How:**
1. Add field whitelist middleware before `finale` processes `POST /api/Users` in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Allow only: `email`, `password`, `passwordRepeat`, `securityQuestion`, `securityAnswer`, `captcha`, `captchaId`

```typescript
const allowedRegistrationFields = ['email', 'password', 'passwordRepeat', 'securityQuestion', 'securityAnswer', 'captchaId', 'captcha']
app.post('/api/Users', (req, res, next) => {
  Object.keys(req.body).forEach(key => {
    if (!allowedRegistrationFields.includes(key)) delete req.body[key]
  })
  next()
})
```

**Verification:** `POST /api/Users` with `role: 'admin'` — created user must have `role: 'customer'`.

---

#### <a id="m-011"></a>M-011 — Add Ownership Verification to Basket Retrieval

**Addresses:** [T-011](#t-011) (IDOR on Basket — High)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The basket route retrieves a basket by ID alone with no check that the basket belongs to the requesting user, enabling any authenticated user to access any other user's basket by guessing integer IDs.

**How:**
1. Add `UserId` to the `where` clause in `BasketModel.findOne()` at [routes/basket.ts](vscode://file/home/mrohr/juice-shop/routes/basket.ts)
2. Return 403 when basket is not found or belongs to another user

```typescript
// Before (vulnerable):
BasketModel.findOne({ where: { id: req.params.id }, include: [...] })

// After (safe):
BasketModel.findOne({ where: { id: req.params.id, UserId: user?.data?.id }, include: [...] })
```

**Verification:** User B attempts `GET /rest/basket/<user_A_basket_id>` — expect 403.

---

#### <a id="m-012"></a>M-012 — Add URL Allowlist to Prevent SSRF

**Addresses:** [T-012](#t-012) (SSRF — High)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The profile image URL upload at [routes/profileImageUrlUpload.ts:24](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:24) fetches any URL provided by the user, including cloud metadata endpoints (169.254.169.254) and internal services.

**How:**
1. Add `isSafeImageUrl()` validation before `fetch(url)` in [routes/profileImageUrlUpload.ts](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts)
2. Block private IP ranges and metadata endpoints (169.254.169.254, 192.168.x.x, 10.x.x.x)
3. Require `https:` protocol and a valid image file extension

```typescript
function isSafeImageUrl (url: string): boolean {
  try {
    const parsed = new URL(url)
    if (parsed.protocol !== 'https:') return false
    const blocked = /^(169\.254\.|192\.168\.|10\.|127\.|localhost)/
    if (blocked.test(parsed.hostname)) return false
    return true
  } catch { return false }
}
```

**Verification:** POST `imageUrl=http://169.254.169.254/latest/meta-data/` — expect blocked error, not a fetch attempt.

---

### P3 — Next Quarter

Lower urgency mitigations that address Medium-risk issues. Plan and implement within the next quarter.

---

#### <a id="m-013"></a>M-013 — Replace Security Questions with Email-Based OTP Reset

**Addresses:** [T-015](#t-015) (Weak Security Questions — Medium)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Medium

**Why:** Knowledge-based authentication via security questions is considered deprecated security practice. The questions used in Juice Shop are publicly OSINT-answerable. Email-based OTP requires the attacker to control the user's email account.

**How:**
1. Generate cryptographically random 6-digit OTP with 10-minute expiry on reset request
2. Send OTP to registered email address only
3. Verify OTP server-side before allowing password change
4. Invalidate OTP after one use

**Verification:** Request reset without access to the registered email — expect failure. Reuse the same OTP — expect rejection.

---

#### <a id="m-014"></a>M-014 — Add Rate Limiting to Login Endpoint

**Addresses:** [T-017](#t-017) (Brute Force on Login — Medium)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** The login endpoint has no rate limiting, enabling automated credential stuffing at full network speed. The existing `express-rate-limit` dependency is already present in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts) — this is a one-line addition.

**How:**
1. Add `express-rate-limit` middleware before `POST /rest/user/login` in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Configure: `windowMs: 15 * 60 * 1000`, `max: 10` requests per IP

```typescript
app.post('/rest/user/login',
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }),
  login()
)
```

**Verification:** Send 11 sequential login requests from the same IP — expect the 11th to return 429.

---

#### <a id="m-015"></a>M-015 — Change Password Endpoint to POST and Require Current Password

**Addresses:** [T-018](#t-018) (Password in URL — Medium)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** GET requests with sensitive data in query parameters are logged by every web server, proxy, and browser history. The password change endpoint uses GET, exposing the new password in plaintext in morgan access logs.

**How:**
1. Change `app.get('/rest/user/change-password')` to `app.post()` in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Always require `currentPassword` field in [routes/changePassword.ts](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts) — return 401 if absent

```typescript
// Before: app.get('/rest/user/change-password', changePassword())
app.post('/rest/user/change-password', changePassword())
```

**Verification:** `GET /rest/user/change-password?new=x&repeat=x` — expect 404 or 405.

---

#### <a id="m-016"></a>M-016 — Restrict Prometheus /metrics to Localhost

**Addresses:** [T-019](#t-019) (Metrics Exposure — Medium)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** Prometheus metrics reveal application internals (routes, counts, errors) to unauthenticated internet users, enabling targeted reconnaissance. Restricting to localhost requires zero application changes beyond adding an IP check middleware.

**How:**
1. Add IP check middleware before the metrics handler in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Allow only `127.0.0.1`, `::1`, `::ffff:127.0.0.1`

```typescript
app.use('/metrics', (req, res, next) => {
  const remoteIp = req.socket.remoteAddress ?? ''
  if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remoteIp)) {
    return res.status(403).send('Forbidden')
  }
  next()
})
```

**Verification:** `GET /metrics` from an external IP — expect 403. From localhost — expect Prometheus text format.

---

### P4 — Backlog

Long-term architectural improvements. Low urgency, schedule for future sprints.

---

#### <a id="m-017"></a>M-017 — Migrate JWT Storage to HttpOnly Cookie

**Addresses:** [T-020](#t-020) (JWT in localStorage — Medium)
**Priority:** **P4 — Backlog**
**Severity:** 🟡 Medium
**Effort:** High

**Why:** `localStorage` is accessible to all JavaScript on the same origin, making stored JWTs a target for any successful XSS payload. HttpOnly cookies are inaccessible to JavaScript by design.

**How:**
1. Issue JWT as `HttpOnly Secure SameSite=Strict` cookie from login response in [routes/login.ts](vscode://file/home/mrohr/juice-shop/routes/login.ts)
2. Remove `localStorage.setItem('token')` from the Angular login handler
3. Remove Bearer header injection from `request.interceptor.ts`

```typescript
res.cookie('token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 6 * 60 * 60 * 1000
})
```

**Verification:** After login, `localStorage.getItem('token')` returns `null`. Cookie is marked `HttpOnly` in browser DevTools.

---

#### <a id="m-018"></a>M-018 — Add Global Input Length Limits

**Addresses:** [T-021](#t-021) (Event Loop DoS — Medium)
**Priority:** **P4 — Backlog**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** The body-parser middleware has no size limit configured, allowing arbitrarily large request bodies that can contribute to memory pressure and event loop saturation.

**How:**
1. Set body-parser size limits: `bodyParser.json({ limit: '100kb' })`
2. Add per-field `maxLength` validation on all POST/PUT routes

```typescript
app.use(bodyParser.json({ limit: '100kb' }))
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }))
```

**Verification:** POST `/api/Users` with a 200 KB JSON body — expect 413 Payload Too Large.

---

#### <a id="m-019"></a>M-019 — Restrict CORS to Specific Origins

**Addresses:** [T-023](#t-023) (Wildcard CORS — Low)
**Priority:** **P4 — Backlog**
**Severity:** 🟢 Low
**Effort:** Low

**Why:** The current `cors()` call with no options allows any origin to make credentialed cross-origin requests to the API. In practice, the lack of CSP is a more severe issue, but CORS should still be scoped.

**How:**
1. Replace `cors()` with `cors({ origin: process.env.ALLOWED_ORIGINS?.split(','), credentials: true })`
2. Set `ALLOWED_ORIGINS` environment variable to the actual frontend origin

```typescript
app.use(cors({
  origin: (process.env.ALLOWED_ORIGINS ?? 'http://localhost:3000').split(','),
  credentials: true
}))
```

**Verification:** Cross-origin request from a disallowed origin — expect no `Access-Control-Allow-Origin` in response.

---

## 10. Out of Scope

Areas deliberately excluded from this assessment:

- Intentional vulnerabilities by design — this is a security training platform; all vulnerabilities documented are intentional and known to the project maintainers
- Challenge-solving infrastructure (`challengeUtils.ts`, scoring system, anti-cheat mechanisms) — these are training harness components, not production security controls
- OAuth/Google login flow — limited scope for quick assessment depth
- Web3/NFT/blockchain features (`routes/web3Wallet.ts`, `routes/nftMint.ts`) — specialized attack surface beyond standard STRIDE scope
- i18n translation infrastructure (Crowdin integration, `i18n/` directory)
- CTF key management (`ctf.key`)
- Grunt build pipeline security
- CI/CD pipeline (GitHub Actions) — not analyzed at quick depth; would require standard/thorough assessment

---

## 11. Changelog

This section records the assessment history for this threat model.

| Version | Date | Mode | Components Re-analyzed | Notes |
|---------|------|------|------------------------|-------|
| v2 | 2026-04-13 | full (--full rebuild) | rest-api, auth-service, frontend-spa | Same commit SHA as v1; changelog preserved |
| v1 | 2026-04-12 | full | rest-api, frontend-spa, auth-service, admin-panel, file-upload-service | Initial assessment |

---

## Appendix: Run Statistics

| Field | Value |
|-------|-------|
| Mode | full (--full rebuild) |
| Assessment Depth | quick |
| Plugin Version | 0.9.0-beta |
| Analysis Version | 1 |
| Total Duration | 2 min 46 s |
| Threats Found | 23 (Critical: 4, High: 8, Medium: 8+1 extra row, Low: 3) |
| Mitigations Generated | 19 |
| Components Analyzed | 3 (rest-api, auth-service, frontend-spa); 2 carried forward |
| Context Cache | hit (context-resolver skipped) |

<details>
<summary>Per-phase duration breakdown</summary>

| Phase | Description | Duration |
|-------|-------------|----------|
| Phase 1 | Context Resolution | cache hit (skipped) |
| Phase 2 | Reconnaissance (inline) | 1 min 04 s |
| Phase 3 | Architecture Modeling | ~15 s |
| Phase 4 | Attack Walkthroughs | ~5 s |
| Phase 5 | Asset Identification | ~2 s |
| Phase 6 | Attack Surface Mapping | ~3 s |
| Phase 7 | Trust Boundary Analysis | ~2 s |
| Phase 8 | Security Controls Catalog | ~10 s |
| Phase 9 | STRIDE Enumeration (inline) | ~2 min |
| Phase 10 | Scan Synthesis | ~1 s |
| Phase 11 | Finalization + Write | ~30 s |

</details>
