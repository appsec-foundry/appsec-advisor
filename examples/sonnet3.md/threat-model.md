# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-09T17:57:02Z |
| Analysis Duration | 17 min 51 s |
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
- [4. Assets](#4-assets)
- [5. Attack Surface](#5-attack-surface)
- [6. Trust Boundaries](#6-trust-boundaries)
- [7. Identified Security Controls](#7-identified-security-controls)
- [7b. Requirements Compliance](#7b-requirements-compliance)
- [8. Threat Register](#8-threat-register)
- [9. Critical Findings](#9-critical-findings)
- [10. Mitigation Register](#10-mitigation-register)
- [11. Out of Scope](#11-out-of-scope)

---

## Management Summary

This threat model identified **30 threats** across 5 components of OWASP Juice Shop v19.2.1, with the following risk distribution:

| Risk Level | Count | Key Areas |
|------------|-------|-----------|
| 🔴 Critical | 6 | SQL injection login/search, RCE via eval, XXE, hardcoded RSA key, MD5 passwords, mass assignment |
| 🟠 High | 16 | NoSQL injection, CORS wildcard, SSRF, XSS token theft, FTP exposure, log disclosure, unprotected admin config |
| 🟡 Medium | 6 | Open redirect, CSRF absent, weak auth guard, admin audit gap, unstructured logging, outdated JWT libs |
| 🟢 Low | 2 | Cookie secret weak, token expiry not validated client-side |

### Key Strengths

- Container runs as non-root (UID 65532) on a distroless base image — limits post-exploitation lateral movement ([Dockerfile:40](vscode://file/home/mrohr/juice-shop/Dockerfile:40))
- SBOM generation integrated into Docker build via CycloneDX — enables supply chain visibility ([Dockerfile:19](vscode://file/home/mrohr/juice-shop/Dockerfile:19))
- CodeQL SAST on every push/PR via `.github/workflows/codeql-analysis.yml` with `security-extended` query suite
- ZAP dynamic scan runs weekly against the production preview instance (`.github/workflows/zap_scan.yml`)

### Requirements Compliance

**Baseline:** [OWASP Security Requirements](https://owasp.org/Top10/) (remote, 25 requirements checked)
**Result:** 25 requirements checked — ✅ 4 PASS · ❌ 13 FAIL · ❌ 3 ANTI-PATTERN · ⚠️ 5 PARTIAL

**⚠ Architectural violations:**
- **[WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — No Sensitive Data in Client Storage:** SPA stores JWT access tokens directly in `localStorage`, exposing all sessions to XSS token theft with no BFF pattern in place
- **[AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) — Standard Auth with MFA:** Custom JWT/password auth with no SSO/OIDC provider and optional-only TOTP; violates the architectural requirement for centralized auth with mandatory MFA
- **[DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — No Password Storage:** Passwords stored as MD5 hashes in [`models/user.ts:75`](vscode://file/home/mrohr/juice-shop/models/user.ts:75) — a broken algorithm; requirement mandates delegating auth to a central identity service

Top violated MUST requirements:
- **[IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized Queries:** Raw SQL string interpolation in [`routes/login.ts:35`](vscode://file/home/mrohr/juice-shop/routes/login.ts:35) and [`routes/search.ts:21`](vscode://file/home/mrohr/juice-shop/routes/search.ts:21)
- **[IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — XXE Prevention:** XML parser configured with `noent: true` in [`routes/fileUpload.ts:83`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)
- **[DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secret Manager:** RSA private key and HMAC secrets hardcoded in [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)

→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*

### Top Findings

- **[T-001 — SQL Injection Authentication Bypass](#t-001):** Unauthenticated attacker can log in as any user including admin via SQL injection in the login endpoint, achieving full account takeover
- **[T-002 — Hardcoded RSA Private Key Enables JWT Forgery](#t-002):** Private key in public source code allows forging arbitrary JWT tokens — complete authentication bypass
- **[T-003 — Remote Code Execution via B2B Order eval](#t-003):** Authenticated attacker can execute arbitrary Node.js code on the server via the B2B order endpoint
- **[T-004 — XXE File Disclosure in XML Upload](#t-004):** XML parser with `noent: true` enables reading any server file including `/etc/passwd`
- **[T-005 — SQL Injection in Product Search](#t-005):** UNION-based SQL injection exposes entire SQLite database including all user credentials

### Recommended Priority Actions

1. **[M-001 — Replace Raw SQL with ORM Parameterized Queries](#m-001)** (Effort: Low · addresses 2 threats) — Eliminate SQL injection in login and product search routes
2. **[M-002 — Remove Hardcoded Secrets; Load from Environment](#m-002)** (Effort: Medium · addresses 3 threats) — RSA private key, HMAC secret, cookie secret must be externalized
3. **[M-003 — Replace MD5 with bcrypt for Password Hashing](#m-003)** (Effort: Medium · addresses 2 threats) — Eliminate broken password storage and enable safe credential verification
4. **[M-004 — Disable XXE in XML Parser](#m-004)** (Effort: Low · addresses 1 threat) — Change `noent: true` to `noent: false` in fileUpload.ts
5. **[M-005 — Remove eval from B2B Order Processing](#m-005)** (Effort: Medium · addresses 1 threat) — Replace `vm.runInContext(safeEval(...))` with JSON schema validation

### Overall Security Rating

🔴 **Critical gaps** — The application contains multiple confirmed critical vulnerabilities (SQL injection enabling auth bypass, hardcoded cryptographic secrets, RCE, XXE) that would result in full system compromise in any production deployment. While the distroless container and CodeQL scanning represent sound practices, the application's intentional vulnerability design means it must never be deployed without these issues remediated.

→ *Full details in [Threat Register](#8-threat-register) and [Mitigation Register](#10-mitigation-register).*

---

## 1. System Overview

OWASP Juice Shop is an intentionally vulnerable web application created by Bjoern Kimminich and the OWASP community. It serves as the most widely-used security training, awareness, and CTF platform for modern web application vulnerabilities. The application implements a full e-commerce shop with user registration/login, product catalog, shopping basket, payment, orders, wallet, product reviews, a chatbot, and a scoreboard tracking solved challenges.

**Deployment context:** Node.js 22 / TypeScript monolith backend serving an Angular 17+ SPA. SQLite provides the primary relational store; MarsDB (in-memory MongoDB-like) handles product reviews and orders. The application exposes port 3000 and is containerized via Docker on a distroless base image.

**Complexity tier: Moderate** — single deployable backend unit with distinct frontend layer, multiple data stores, WebSocket, and monitoring stack. Two C4 levels (Context + Containers) are appropriate.

**Compliance scope:** OWASP Top 10 (training platform). No PCI-DSS, HIPAA, or SOC2 requirements identified.

**Repo URL:** https://github.com/juice-shop/juice-shop
**Team owner:** OWASP Juice Shop contributors (bjoern.kimminich@owasp.org)

**Context sources used:** None (no external context endpoint or business-context.md found). Analysis based entirely on repository source code.

**Overall security impression:** This application is intentionally vulnerable by design and contains confirmed Critical-severity vulnerabilities across authentication, injection, and cryptography domains. Positive security practices include distroless containers, non-root execution, CodeQL SAST, CycloneDX SBOM generation, and partial rate limiting. However, the hardcoded RSA private key, MD5 password hashing, wildcard CORS, SQL injection in the login route, and RCE in the B2B order route would be catastrophic in any production context.

---

## 2. Architecture Diagrams

The following diagrams model the system architecture using C4-style conventions. Security-relevant components are highlighted in red (:::risk). Trust boundaries are shown as labeled subgraphs.

### 2.1 System Context

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["🌐 Public Internet · untrusted"]
        User["Anonymous User\nbrowser"]:::person
        AuthUser["Authenticated User\nbrowser"]:::person
        Attacker["Attacker\nbrowser / script"]:::person
    end

    subgraph APP["🔒 Application Zone"]
        JuiceShop["OWASP Juice Shop\nNode.js 22 / Express 4.22\nAngular SPA\nDocker port 3000"]:::risk
    end

    subgraph EXTERNAL["🌐 External Services"]
        GoogleOAuth["Google OAuth 2.0\naccounts.google.com"]:::external
        Prometheus["Prometheus Scraper\nmonitoring"]:::external
    end

    User -->|"GET / · HTTP"| JuiceShop
    AuthUser -->|"REST/WebSocket · HTTP"| JuiceShop
    Attacker -->|"SQLi / RCE / XXE\nHTTP"| JuiceShop
    JuiceShop -->|"OAuth redirect · HTTPS"| GoogleOAuth
    Prometheus -->|"GET /metrics · HTTP (unauthenticated)"| JuiceShop

    %% Trust Boundary Key:
    %% INTERNET→APP: No TLS enforced at app layer (HTTP by default); JWT in localStorage; wildcard CORS
    %% APP→EXTERNAL: HTTPS for Google OAuth; /metrics unauthenticated
```

### 2.2 Containers

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph BROWSER["🌐 Browser · untrusted execution environment"]
        SPA["Angular SPA\nTypeScript · Angular 17+\nJWT in localStorage"]:::risk
    end

    subgraph SERVER["🔒 Node.js Container · UID 65532 · distroless"]
        API["Express REST API\nNode.js 22 / TypeScript\nExpress 4.22 · port 3000"]:::risk
        AuthLib["Auth Module\nlib/insecurity.ts\nJWT RS256 · MD5 passwords"]:::risk
        FileUpload["File Upload Service\nmulter · libxmljs2\nXXE enabled"]:::risk
        Chatbot["Chatbot Service\njuicy-chat-bot\nroutes/chatbot.ts"]:::system
        StaticFiles["Static File Server\nFTP dir · logs dir\nencrption keys dir"]:::risk
    end

    subgraph DATA["🔐 Data Tier · restricted"]
        SQLite["SQLite Database\nsequelize 6.37\nusers · products · orders"]:::db
        MarsDB["MarsDB\nin-memory NoSQL\nreviews · orders"]:::db
        FTPDir["FTP Directory\n/ftp · public files\nsensitive backups"]:::risk
    end

    SPA -->|"REST API · HTTP · Bearer token"| API
    SPA -->|"WebSocket · socket.io"| API
    API -->|"ORM queries · SQLite driver"| SQLite
    API -->|"Collection queries"| MarsDB
    API --> AuthLib
    API --> FileUpload
    API --> Chatbot
    API --> StaticFiles
    StaticFiles -->|"serve-index · file read"| FTPDir

    %% Trust Boundary Key:
    %% BROWSER→SERVER: JWT in localStorage (XSS-accessible); wildcard CORS; no CSRF protection; no HttpOnly cookies
    %% SERVER→DATA: SQLite in-process; MarsDB in-memory; no encryption at rest
    %% FTP: Publicly accessible without authentication
```

### 2.3 Technology Architecture

```mermaid
graph TB
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph CLIENT["Client Layer"]
        ANG["Angular 17+ SPA\nTypeScript strict=OFF\nlocalStorage token"]:::risk
    end

    subgraph MIDDLEWARE["Middleware Layer"]
        HLM["Helmet 4.6\nnoSniff + frameguard only\nNo CSP, No HSTS"]:::risk
        CORS_MW["cors 2.8.5\nWildcard all origins"]:::risk
        JWT_MW["express-jwt 0.1.3\nRS256 verification\nVery old version"]:::risk
        RL["express-rate-limit 7.5.1\nOnly reset-password + 2fa"]:::risk
        ERR["errorhandler\nStack trace disclosure"]:::risk
    end

    subgraph APP_LAYER["Application Layer"]
        ROUTES["61 Route Handlers\nTypeScript"]:::system
        AUTH["lib/insecurity.ts\nMD5 hash · hardcoded RSA key\nHMAC secret inline"]:::risk
        MODELS["Sequelize Models\nSQLite 5.1.7\n20+ models"]:::system
    end

    subgraph DATA_LAYER["Data Layer"]
        SQLITE["SQLite\nIn-process\nNo encryption"]:::db
        MARSDB["MarsDB\nIn-memory NoSQL\nNoSQL injection risk"]:::risk
    end

    ANG -->|"HTTP · Bearer token"| HLM
    HLM -->|"Express middleware chain"| CORS_MW
    CORS_MW -->|"All origins allowed"| JWT_MW
    JWT_MW -->|"Parsed token"| RL
    RL -->|"Routes"| ROUTES
    ROUTES --> AUTH
    ROUTES --> MODELS
    MODELS -->|"SQL · Sequelize"| SQLITE
    ROUTES -->|"Collection API"| MARSDB
```

### 2.4 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ❌ No | No gateway layer; Express serves all traffic directly |
| BFF (Backend-for-Frontend) | ❌ No | JWT stored in browser `localStorage`; no server-side session proxy |
| Defense-in-depth | ⚠️ Partial | Helmet applied partially; no CSP; no WAF; rate limiting on 3 routes only |
| Separation of concerns | ✅ Yes | Routes, models, lib clearly separated; Angular frontend independently compiled |
| Least privilege | ⚠️ Partial | Container runs non-root (UID 65532); but multiple admin endpoints unauthenticated |
| Secrets management | ❌ No | RSA private key, HMAC key, cookie secret all hardcoded in source |
| Network segmentation | ❌ No | All endpoints on same port 3000; no internal vs external port separation |
| Secure defaults | ❌ No | CORS wildcard; XXE enabled; MD5 hashing; errorhandler() stack traces |

#### Trust Model Evaluation

The application does **not** implement a fail-closed trust model. Unauthenticated requests reach multiple sensitive endpoints (`/rest/admin/application-configuration`, `/metrics`, `/ftp/*`, `/support/logs/*`, `/encryptionkeys/*`). The CORS configuration allows all origins, meaning the server implicitly trusts any domain's JavaScript. The JWT `isAuthorized()` middleware is correctly applied on most REST routes but is missing on admin configuration endpoints. Implicit trust exists at the browser-server boundary — the `X-User-Email` header sent from localStorage is processed without independent verification. There is no unnecessary transitivity within the server-side code, but the trust boundary between browser and server is severely weakened by localStorage token storage and wildcard CORS.

#### Authentication and Authorization Architecture

The authentication architecture is entirely custom: Express-JWT validates RS256-signed JWTs, with the private key embedded in [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts). There is no standard SSO or OIDC provider — authentication is a bespoke username/password flow with optional TOTP. This represents a **systemic architectural gap**: the absence of a centralized identity provider means no MFA enforcement, no centralized session revocation, no audit trail, and no ability to federate with enterprise identity systems.

Authorization uses a flat role model (`customer`, `deluxe`, `accounting`, `admin`) embedded in JWT claims. Role verification happens inline in route handlers via [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) helpers. There is no authorization service or policy engine — each route independently checks the role. This creates inconsistency risk (some admin routes are checked, others are not).

#### Key Architectural Risks

| # | Structural Risk | Impact if exploited | Linked threats |
|---|----------------|---------------------|----------------|
| 1 | No BFF pattern — tokens in browser localStorage | Any XSS → full session theft for all logged-in users | [T-016](#t-016), [T-017](#t-017) |
| 2 | Wildcard CORS across all endpoints | Any website can make credentialed API calls on behalf of victims | [T-010](#t-010) |
| 3 | Custom auth instead of standard OIDC/SSO | No centralized revocation, MFA, or audit; custom JWT library vulnerabilities | [T-002](#t-002), [T-006](#t-006) |
| 4 | No secrets management — keys in source | Full auth bypass if source is read; no rotation possible | [T-002](#t-002), [T-007](#t-007) |
| 5 | Public file serving without auth (FTP, logs, keys) | Direct credential and configuration exfiltration | [T-012](#t-012), [T-023](#t-023) |

#### Overall Architecture Security Rating

🔴 **Critical gaps** — The application is built on fundamentally insecure architectural foundations: secrets in source code, wildcard CORS, no BFF pattern, no CSP, custom authentication without a standard identity provider, and multiple unauthenticated administrative endpoints. While the containerization (distroless, non-root) and CI security scanning represent modern good practices, the application's core security architecture requires a complete rearchitecture to be suitable for production use.

---

## 3. Security-Relevant Use Cases

These sequence diagrams document security-critical flows showing both normal operation and the primary attack vectors identified in this assessment.

### 3.1 Authentication Flow (with SQL Injection Attack Path)

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as Express API
    participant DB as SQLite

    U->>API: POST /rest/user/login {email, password}
    Note over API: No rate limiting on this endpoint
    API->>DB: SELECT * FROM Users WHERE email='${email}' AND password='${md5(pw)}'
    Note over DB: VULNERABLE: raw string interpolation
    alt Normal login
        DB-->>API: User row or empty
        API-->>U: {token: JWT_RS256, bid: basketId}
        Note over U: Token stored in localStorage.setItem('token', ...)
    else SQL Injection Attack
        U->>API: POST /rest/user/login {email: "' OR 1=1--", password: "x"}
        API->>DB: SELECT * FROM Users WHERE email='' OR 1=1-- AND password=...
        DB-->>API: First user row (admin)
        API-->>U: Admin JWT token
        Note over U: Full admin access without credentials
    end
```

### 3.2 Frontend Security — XSS Token Theft

```mermaid
sequenceDiagram
    participant A as Attacker
    participant V as Victim Browser
    participant API as Express API
    participant LS as localStorage

    A->>API: PUT /rest/products/1/reviews {message: "<script>..."}
    Note over API: sanitize-html 1.4.2 (old, bypassable)
    API-->>A: 201 Created

    V->>API: GET / (loads Angular app)
    V->>API: GET /rest/products/1/reviews
    API-->>V: Review with persisted XSS payload
    Note over V: bypassSecurityTrustHtml used — XSS executes
    V->>LS: localStorage.getItem('token')
    LS-->>V: JWT token value
    V->>A: Token exfiltrated to attacker server
    A->>API: API requests as victim using stolen token
```
<!-- QA: sequence diagram '3.2 Frontend Security — XSS Token Theft' has no alt/else failure path — consider adding error scenarios (sanitization blocks payload, auth token revoked, etc.) -->

### 3.3 File Upload — XXE Attack Path

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant FS as File System

    A->>API: POST /file-upload (XML with XXE payload)
    Note over A: Content: xml with ENTITY xxe SYSTEM file:///etc/passwd
    API->>FS: libxml.parseXml(data, {noent: true})
    Note over FS: noent:true resolves external entities
    FS-->>API: File contents included in parsed XML
    API-->>A: 410 Error includes parsed XML content
    Note over A: /etc/passwd contents returned in error message
```
<!-- QA: sequence diagram '3.3 File Upload — XXE Attack Path' has no alt/else failure path — consider adding error scenarios (noent disabled, file not found, etc.) -->

### 3.4 B2B Order — Remote Code Execution

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant VM as Node.js vm

    A->>API: POST /b2b/v2/orders {orderLinesData: "process.mainModule..."}
    Note over API: JWT required (isAuthorized check)
    API->>VM: vm.createContext({safeEval, orderLinesData})
    VM->>VM: vm.runInContext("safeEval(orderLinesData)", sandbox)
    Note over VM: notevil sandbox escape possible
    VM-->>API: RCE executed on server
    API-->>A: Error or response revealing server state
```
<!-- QA: sequence diagram '3.4 B2B Order — Remote Code Execution' has no alt/else failure path — consider adding error scenarios (invalid order format, sandbox timeout, etc.) -->

---

## 4. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to threats that target them.

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| User credentials (email + MD5 hash) | Confidential | All user account credentials in SQLite `Users` table | [T-001](#t-001), [T-003](#t-003), [T-005](#t-005) |
| RSA JWT private key | Restricted | Signs all authentication tokens; exposed in [`lib/insecurity.ts:22`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:22) | [T-002](#t-002) |
| HMAC secret | Restricted | Used for coupon and deluxe token signing; hardcoded in [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44) | [T-007](#t-007) |
| JWT authentication tokens | Confidential | 6-hour RS256 tokens stored in `localStorage` | [T-016](#t-016), [T-017](#t-017) |
| Payment card data | Confidential | Card numbers in `CardModel`; user wallet balances | [T-001](#t-001), [T-010](#t-010) |
| Order history and PII | Confidential | Customer names, addresses, order details in SQLite and MarsDB | [T-005](#t-005), [T-009](#t-009), [T-010](#t-010) |
| Application source code | Internal | TypeScript source including hardcoded secrets; FTP backups | [T-012](#t-012) |
| Access logs | Internal | Morgan combined logs at `/support/logs/` — contain Authorization headers | [T-023](#t-023) |
| Server filesystem | Restricted | `/etc/passwd` and other server files accessible via XXE | [T-004](#t-004) |
| Application configuration | Internal | Full config object exposed at `/rest/admin/application-configuration` | [T-020](#t-020) |

---

## 5. Attack Surface

All identified entry points through which an attacker can interact with the system, including protocol, authentication requirements, and linked threats.

| Entry Point | Protocol/Method | Authentication | Notes | Linked Threats |
|-------------|----------------|----------------|-------|----------------|
| `POST /rest/user/login` | HTTP POST | None | SQL injection; no rate limit | [T-001](#t-001) |
| `GET /rest/products/search?q=` | HTTP GET | None | SQL injection via `q` param | [T-005](#t-005) |
| `POST /b2b/v2/orders` | HTTP POST | JWT required | RCE via eval on orderLinesData | [T-003](#t-003) |
| `POST /file-upload` | HTTP POST multipart | None | XXE on XML; path traversal on ZIP | [T-004](#t-004), [T-026](#t-026) |
| `POST /profile/image/url` | HTTP POST | Cookie token | SSRF via imageUrl | [T-013](#t-013), [T-027](#t-027) |
| `GET /ftp/*` | HTTP GET | None | Public file listing; sensitive backups | [T-012](#t-012) |
| `GET /encryptionkeys/*` | HTTP GET | None | JWT public key; premium key | [T-012](#t-012) |
| `GET /support/logs/*` | HTTP GET | None | Application log file download | [T-023](#t-023) |
| `GET /metrics` | HTTP GET | None | Prometheus metrics unauthenticated | [T-014](#t-014) |
| `GET /rest/admin/application-configuration` | HTTP GET | None | Full config object exposed | [T-020](#t-020) |
| `GET /rest/admin/application-version` | HTTP GET | None | Version disclosure | [T-020](#t-020) |
| `PATCH /rest/products/reviews` | HTTP PATCH | JWT required | NoSQL injection via `id` body field | [T-008](#t-008) |
| `GET /rest/track-order/:id` | HTTP GET | None | NoSQL injection via orderId | [T-009](#t-009) |
| `GET /redirect?to=` | HTTP GET | None | Open redirect | [T-015](#t-015) |
| `PUT /rest/products/:id/reviews` | HTTP PUT | None | Stored XSS via review message | [T-017](#t-017) |
| `POST /api/Users` | HTTP POST | None | Mass assignment to set role=admin | [T-021](#t-021) |
| `POST /rest/chatbot/respond` | HTTP POST | JWT required | Chatbot prompt injection | [T-028](#t-028) |
| `GET /api-docs` | HTTP GET | None | Swagger UI — B2B API documentation | — |
| `WebSocket /socket.io` | WebSocket | None | Real-time event channel | — |

---

## 6. Trust Boundaries

Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk.

The overall trust model is permissive-by-default: the application extends implicit trust to many sources (all browser origins via wildcard CORS, unauthenticated requests to admin endpoints, arbitrary URLs for SSRF), rather than denying by default and requiring explicit authorization.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|--------------|----------------|
| 1 | Browser → Server | Public internet (browser) | Express API | JWT in Authorization header; cookie token | Wildcard CORS; JWT in localStorage (XSS-accessible); no CSRF protection | [T-010](#t-010), [T-016](#t-016), [T-019](#t-019) |
| 2 | Unauthenticated → Authenticated | Anonymous | JWT-verified session | `security.isAuthorized()` middleware (express-jwt) | SQL injection bypasses auth entirely; old express-jwt 0.1.3 | [T-001](#t-001), [T-006](#t-006) |
| 3 | Customer → Admin | `customer` role | `admin` role | JWT role claim check in [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) | Mass assignment allows role escalation; admin config endpoints unprotected | [T-020](#t-020), [T-021](#t-021) |
| 4 | Server → File System | Express process | OS file system | OS process permissions (UID 65532, distroless) | XXE reads arbitrary files; ZIP path traversal; SSRF fetches internal resources | [T-004](#t-004), [T-026](#t-026), [T-027](#t-027) |

**Boundary 1 note:** The wildcard CORS (`app.use(cors())`) eliminates the browser same-origin policy as a security control. Any malicious website visited by an authenticated Juice Shop user can make full API calls using the victim's session, as if operating from the same origin. This affects all authenticated endpoints.

**Boundary 3 note:** The `/rest/admin/application-configuration` and `/rest/admin/application-version` endpoints have no authorization check at all (server.ts:604-605) despite being in the `/rest/admin/` namespace.

---

## 7. Identified Security Controls

The following critical gaps represent the most severe missing controls: (1) No Content-Security-Policy — makes XSS exploitation trivial, (2) Wildcard CORS — eliminates cross-origin protection for all users, (3) No CSRF protection — all state-changing operations can be triggered cross-site, (4) No secrets management — private keys and HMAC secrets in source code, (5) No BFF pattern — JWT tokens exposed to JavaScript in localStorage. Any one of these gaps independently enables a high-impact attack; together they represent systemic exposure.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

<!-- QA: Section 7 gap summary is present as a narrative paragraph above but does not use the "Gap summary:" label — consider prefixing with **Gap summary:** for clarity -->

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|---------------|---------------|----------------|
| IAM | Authentication | Custom JWT RS256 via express-jwt 0.1.3 — [`lib/insecurity.ts:54`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) | 🔶 Weak | [T-001](#t-001), [T-002](#t-002), [T-006](#t-006) |
| IAM | Password hashing | MD5 via `crypto.createHash('md5')` — [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) | ❌ Missing | [T-003](#t-003) |
| IAM | 2FA/MFA | Optional TOTP via `otplib` — [`routes/2fa.ts`](vscode://file/home/mrohr/juice-shop/routes/2fa.ts) | ⚠️ Partial | — |
| Authorization | Route-level RBAC | `security.isAuthorized()` on most routes — `server.ts:350+` | ⚠️ Partial | [T-020](#t-020), [T-021](#t-021) |
| Authorization | Resource-level IDOR check | Basket IDOR check allows access before blocking — [`routes/basket.ts:20`](vscode://file/home/mrohr/juice-shop/routes/basket.ts:20) | 🔶 Weak | [T-021](#t-021) |
| Data Protection | Transport encryption | HTTP by default; no TLS enforced at app level | ❌ Missing | [T-010](#t-010) |
| Data Protection | Data at rest | No encryption; SQLite in plaintext | ❌ Missing | [T-005](#t-005) |
| Secret Management | Key/secret storage | RSA private key, HMAC key, cookie secret hardcoded in source | ❌ Missing | [T-002](#t-002), [T-007](#t-007) |
| Frontend Security | XSS prevention | Angular interpolation used but `bypassSecurityTrustHtml` in 4 components | 🔶 Weak | [T-016](#t-016), [T-017](#t-017) |
| Frontend Security | Token storage | JWT in `localStorage` — `request.interceptor.ts:13` | ❌ Missing | [T-016](#t-016) |
| Output Encoding | API response encoding | Express JSON serialization; no HTML encoding for API responses | ⚠️ Partial | [T-017](#t-017) |
| CSP | Content-Security-Policy | Not configured (`helmet.contentSecurityPolicy()` not called) | ❌ Missing | [T-017](#t-017), [T-018](#t-018) |
| CORS | Cross-Origin Resource Sharing | Wildcard: `app.use(cors())` — `server.ts:182` | ❌ Missing | [T-010](#t-010) |
| Audit & Logging | Access logging | Morgan combined format — `server.ts:328` | ⚠️ Partial | [T-022](#t-022) |
| Audit & Logging | Security event logging | Winston console logger, no structured security events | 🔶 Weak | [T-022](#t-022) |
| Audit & Logging | Log protection | Logs publicly accessible at `/support/logs/` | ❌ Missing | [T-023](#t-023) |
| Infrastructure | Container security | Distroless base; non-root UID 65532 — `Dockerfile:40` | ✅ Adequate | — |
| Infrastructure | SBOM generation | CycloneDX via Docker build — `Dockerfile:19` | ✅ Adequate | — |
| Infrastructure | Security headers | noSniff + frameguard only; no CSP, no HSTS, no Referrer-Policy | 🔶 Weak | [T-018](#t-018) |
| Dependency & Supply Chain | CVE scanning | No `npm audit` in CI; CodeQL SAST present | ⚠️ Partial | [T-025](#t-025) |
| Dependency & Supply Chain | Lockfile pinning | No `package-lock.json` in repository root | ❌ Missing | [T-025](#t-025) |
| Dependency & Supply Chain | CI action pinning | Most pinned to SHA; CodeQL uses mutable `@v3` tags | ⚠️ Partial | [T-025](#t-025) |
| Dependency & Supply Chain | Container image hygiene | Base images use mutable tags (`node:24`, not digest) | 🔶 Weak | [T-025](#t-025) |
| Security Testing | SAST | CodeQL `security-extended` on every push/PR | ✅ Adequate | — |
| Security Testing | DAST | ZAP baseline scan weekly on preview instance | ✅ Adequate | — |
| Input Validation | SQL injection prevention | Raw SQL string interpolation in login and search | ❌ Missing | [T-001](#t-001), [T-005](#t-005) |
| Input Validation | NoSQL injection prevention | Unsanitized `$where` and `_id` in MarsDB queries | ❌ Missing | [T-008](#t-008), [T-009](#t-009) |
| Input Validation | XXE prevention | `noent: true` explicitly set — [`routes/fileUpload.ts:83`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) | ❌ Missing | [T-004](#t-004) |
| OAuth/OIDC | Standard OIDC flow | No OIDC provider; custom Google OAuth client | ❌ Missing | [T-024](#t-024) |
| SPA/BFF Architecture | BFF pattern | No BFF; Angular SPA directly holds JWT in localStorage | ❌ Missing | [T-016](#t-016) |

---

## 7b. Requirements Compliance

This section summarizes the compliance status of each requirement from the [OWASP Security Requirements](https://owasp.org/Top10/) baseline. Requirements marked ❌ FAIL or ❌ ANTI-PATTERN have generated threat entries in the [Threat Register](#8-threat-register).

### Architectural Violations

These findings represent **systemic architectural gaps** — missing patterns or standard services that have cascading security impact beyond individual controls.

| Violation | Priority | Evidence | Risk | Linked Threats |
|-----------|----------|----------|------|----------------|
| [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — No Sensitive Data in Client Storage | MUST | JWT token stored in `localStorage` via `request.interceptor.ts:13` — all sessions exposed to any XSS | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | [T-016](#t-016) |
| [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) — Centralized Auth with MFA | MUST | Custom JWT/password auth; no SSO/OIDC provider; TOTP optional only | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | [T-024](#t-024) |
| [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — No Password Storage / Delegate to IdP | MUST | MD5 hashing in [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) — broken algorithm; passwords stored locally | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | [T-003](#t-003) |

### Full Compliance Table

| Requirement | Priority | Title | Status | Evidence | Linked Threats |
|-------------|----------|-------|--------|----------|----------------|
| [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) | MUST | No sensitive data in client storage | ❌ ANTI-PATTERN | JWT in `localStorage` — `request.interceptor.ts:13` | [T-016](#t-016) |
| [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | MUST | Centralized auth with MFA | ❌ ANTI-PATTERN | Custom auth; TOTP optional; no OIDC | [T-024](#t-024) |
| [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | MUST | Delegate password storage to IdP | ❌ ANTI-PATTERN | MD5 hashing in [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) | [T-003](#t-003) |
| [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | MUST | Parameterized queries | ❌ FAIL | Raw SQL in [`routes/login.ts:35`](vscode://file/home/mrohr/juice-shop/routes/login.ts:35), [`routes/search.ts:21`](vscode://file/home/mrohr/juice-shop/routes/search.ts:21) | [T-001](#t-001), [T-005](#t-005) |
| [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | MUST | Harden XML parsers against XXE | ❌ FAIL | `noent: true` in [`routes/fileUpload.ts:83`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) | [T-004](#t-004) |
| [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | MUST | Secrets in dedicated secret manager | ❌ FAIL | RSA key, HMAC secret, cookie secret hardcoded in [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) | [T-002](#t-002), [T-007](#t-007) |
| [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | MUST | Restrictive CORS allowlist | ❌ FAIL | Wildcard CORS in `server.ts:182` | [T-010](#t-010) |
| [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | MUST | Anti-CSRF protection | ❌ FAIL | No CSRF protection; no SameSite cookies | [T-019](#t-019) |
| [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | MUST | HSTS header | ❌ FAIL | No HSTS configured in `server.ts` | [T-018](#t-018) |
| [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | MUST | Encode output to prevent XSS | ❌ FAIL | `bypassSecurityTrustHtml` in `about.component.ts:119`, `last-login-ip.component.ts:39` | [T-017](#t-017) |
| [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | MUST | Secure state on error; no internal detail disclosure | ❌ FAIL | `errorhandler()` leaks stack traces — `server.ts:676` | [T-011](#t-011) |
| [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | MUST | Management endpoints not reachable publicly | ❌ FAIL | `/rest/admin/*`, `/metrics`, `/support/logs/` all public | [T-014](#t-014), [T-020](#t-020), [T-023](#t-023) |
| [SC-001](https://owasp.org/www-project-dependency-check/) | MUST | Automated SCA in CI pipeline | ❌ FAIL | No `npm audit` or Snyk in CI workflows | [T-025](#t-025) |
| [SC-002](https://owasp.org/www-project-dependency-check/) | MUST | Pin dependencies with lockfile | ❌ FAIL | No `package-lock.json` in repository | [T-025](#t-025) |
| [IF-002](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | MUST | Non-root container | ✅ PASS | `USER 65532` in `Dockerfile:40` | — |
| [HN-001](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | MUST | Disable X-Powered-By | ✅ PASS | `app.disable('x-powered-by')` — `server.ts:188` | — |
| [SC-006](https://owasp.org/www-community/controls/Static_Code_Analysis) | MUST | SAST in CI pipeline | ✅ PASS | CodeQL `security-extended` in `.github/workflows/codeql-analysis.yml` | — |
| [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | MUST | Rate limiting on all external endpoints | ⚠️ PARTIAL | Rate limit only on `/rest/user/reset-password` and `/rest/2fa/*`; login unprotected | [T-029](#t-029) |
| [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | MUST | Log all security events | ⚠️ PARTIAL | Morgan access log present; no structured security event logging | [T-022](#t-022) |
| [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | SHOULD | CSP headers | ❌ FAIL | No CSP configured; `helmet.xssFilter()` commented out | [T-018](#t-018) |
| [WEB-006](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html) | MUST | Maintained frameworks; TypeScript strict mode | ⚠️ PARTIAL | Angular used (maintained); TypeScript strict mode not enabled in `tsconfig.base.json` | — |
| [IF-007](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | SHOULD | Pin base images to digest | ⚠️ PARTIAL | `FROM node:24` uses mutable tag; no SHA256 digest | [T-025](#t-025) |
| [SC-004](https://owasp.org/www-project-cyclonedx/) | SHOULD | SBOM for each release | ✅ PASS | CycloneDX in `Dockerfile:19`; `npm run sbom` | — |
| [LM-002](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | MUST | Structured log format | ⚠️ PARTIAL | Winston `format.simple()` not JSON; Morgan combined format is structured | [T-022](#t-022) |
| [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | MUST | RBAC; deny by default | ⚠️ PARTIAL | Role model present but admin endpoints unprotected; no deny-by-default pattern | [T-020](#t-020) |

**Summary:** 25 requirements checked — ✅ 4 PASS · ❌ 13 FAIL · ❌ 3 ANTI-PATTERN · ⚠️ 5 PARTIAL

---

## 8. Threat Register

**Risk methodology:** Risk = Likelihood × Impact. Likelihood considers exploitability, attack complexity, and required privileges. Impact considers confidentiality, integrity, and availability effects on the identified assets. Ratings: Critical, High, Medium, Low.

**Risk Distribution:** Critical: 6 · High: 16 · Medium: 6 · Low: 2 · **Total: 30**
**STRIDE Coverage:** Spoofing: 5 · Tampering: 7 · Repudiation: 3 · Information Disclosure: 9 · Denial of Service: 3 · Elevation of Privilege: 3

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>[T-001](#t-001) | Auth Service | Spoofing | Login endpoint uses raw SQL: `SELECT * FROM Users WHERE email = '${req.body.email}'` — [`routes/login.ts:35`](vscode://file/home/mrohr/juice-shop/routes/login.ts:35). Attacker sends `' OR 1=1--` to authenticate as any user without credentials. (CWE-89) Violated: [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | MD5 password hashing (insufficient) | [M-001](#m-001) |
| <a id="t-002"></a>[T-002](#t-002) | Auth Service | Tampering | RSA private key hardcoded in [`lib/insecurity.ts:22`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:22) — any source code reader can forge arbitrary JWT tokens for any user/role. Public repo exposure makes this trivially exploitable. (CWE-321) Violated: [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT signed RS256 — but private key is public | [M-002](#m-002) |
| <a id="t-003"></a>[T-003](#t-003) | Auth Service | Information Disclosure | Passwords hashed with MD5 ([`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43)). Any database breach (via SQLi T-001 or T-005) immediately yields crackable MD5 hashes — GPU cracking recovers common passwords in seconds. (CWE-916) Violated: [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | MD5 hashing applied (broken algorithm) | [M-003](#m-003) |
| <a id="t-004"></a>[T-004](#t-004) | File Upload Service | Information Disclosure | XML upload at `POST /file-upload` processes with `noent: true` ([`routes/fileUpload.ts:83`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)), enabling XXE. Attacker uploads XML with `SYSTEM file:///etc/passwd` entity — file contents returned in error response body. (CWE-611) Violated: [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — noent explicitly enabled | [M-004](#m-004) |
| <a id="t-005"></a>[T-005](#t-005) | REST API | Tampering | Product search `GET /rest/products/search?q=` uses raw SQL: `SELECT * FROM Products WHERE name LIKE '%${criteria}%'` — [`routes/search.ts:21`](vscode://file/home/mrohr/juice-shop/routes/search.ts:21). UNION injection dumps all tables including `Users` with MD5 password hashes. (CWE-89) Violated: [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Length truncation to 200 chars (insufficient) | [M-001](#m-001) |
| <a id="t-006"></a>[T-006](#t-006) | REST API | Tampering | B2B order `POST /b2b/v2/orders` evaluates `orderLinesData` via `vm.runInContext('safeEval(orderLinesData)', sandbox)` — [`routes/b2bOrder.ts:22`](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:22). notevil sandbox escape enables RCE on the Node.js process — reading files, making network calls, spawning processes. (CWE-94) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | notevil sandbox (bypassable), 2s timeout | [M-005](#m-005) |
| <a id="t-007"></a>[T-007](#t-007) | Auth Service | Spoofing | HMAC key hardcoded in [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44) (`pa4q****`). Attacker uses known key to generate valid coupon codes and forge deluxe membership tokens, obtaining discounts and premium features without payment. (CWE-321) Violated: [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | HMAC applied (but key is public) | [M-002](#m-002) |
| <a id="t-008"></a>[T-008](#t-008) | REST API | Tampering | Product review update `PATCH /rest/products/reviews` uses `{ _id: req.body.id }` with `{ multi: true }` — [`routes/updateProductReviews.ts:18`](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:18). Sending `{ "$gt": "" }` as id matches all documents, overwriting all reviews simultaneously. (CWE-943) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT auth required | [M-006](#m-006) |
| <a id="t-009"></a>[T-009](#t-009) | REST API | Information Disclosure | Order tracking `GET /rest/track-order/:id` uses `$where: \`this.orderId === '${id}'\`` — [`routes/trackOrder.ts:18`](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:18). JavaScript injection via `$where` enables cross-user order enumeration and timing-based data exfiltration. (CWE-943) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Partial input sanitization on non-challenge path | [M-006](#m-006) |
| <a id="t-010"></a>[T-010](#t-010) | REST API | Information Disclosure | Wildcard CORS: `app.use(cors())` — `server.ts:182`. Any cross-origin site can make credentialed API requests using victim's JWT token. Attacker hosts malicious page, victim visits and their cart is checked out, PII exfiltrated. (CWE-942) Violated: [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-007](#m-007) |
| <a id="t-011"></a>[T-011](#t-011) | REST API | Information Disclosure | `errorhandler()` middleware (`server.ts:676`) sends full Node.js stack traces in HTTP error responses. Reveals file paths, application structure, Express version, and SQLite schema details to attackers. (CWE-209) Violated: [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-008](#m-008) |
| <a id="t-012"></a>[T-012](#t-012) | REST API | Information Disclosure | FTP directory at `/ftp` publicly browsable via `serve-index` — `server.ts:255`. Files include `incident-support.kdbx` (KeePass DB), `coupons_2013.md.bak`, `package-lock.json.bak`. `/encryptionkeys/` also browsable — JWT public key and premium.key exposed. (CWE-548) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-009](#m-009) |
| <a id="t-013"></a>[T-013](#t-013) | REST API | Spoofing | SSRF via `POST /profile/image/url` — [`routes/profileImageUrlUpload.ts:26`](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:26). Server fetches arbitrary attacker-supplied URL. Can reach cloud metadata endpoints (`http://169.254.169.254/`), internal databases, Redis, or other internal services. (CWE-918) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Cookie token required for auth | [M-010](#m-010) |
| <a id="t-014"></a>[T-014](#t-014) | REST API | Information Disclosure | Prometheus metrics `GET /metrics` unauthenticated — `server.ts:718`. Exposes request counts, error rates, file upload statistics, endpoint names, and internal metrics labels revealing application internals. (CWE-200) Violated: [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-009](#m-009) |
| <a id="t-015"></a>[T-015](#t-015) | REST API | Spoofing | Open redirect `GET /redirect?to=` — [`routes/redirect.ts:15`](vscode://file/home/mrohr/juice-shop/routes/redirect.ts:15). `isRedirectAllowed()` prefix check can be bypassed via URL encoding or open redirects within allowed domains. Enables phishing: victim clicks legitimate Juice Shop URL, lands on attacker site. (CWE-601) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | URL prefix allowlist | [M-011](#m-011) |
| <a id="t-016"></a>[T-016](#t-016) | Frontend SPA | Information Disclosure | JWT stored in `localStorage` — `request.interceptor.ts:13`. Any XSS on any page can call `localStorage.getItem('token')` to steal the 6-hour token, enabling full account takeover. No HttpOnly protection. (CWE-922) Violated: [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-012](#m-012) |
| <a id="t-017"></a>[T-017](#t-017) | Frontend SPA | Tampering | `bypassSecurityTrustHtml` used on user feedback (`about.component.ts:119`), lastLoginIp (`last-login-ip.component.ts:39`), and user emails (`administration.component.ts:60`). Stored XSS executes in other users' browsers, stealing tokens or performing actions. (CWE-79) Violated: [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | sanitize-html 1.4.2 on server (old, bypassable) | [M-013](#m-013) |
| <a id="t-018"></a>[T-018](#t-018) | REST API | Tampering | No Content-Security-Policy configured — `server.ts:187` (xssFilter commented out). No HSTS. Absence of CSP allows XSS payloads to load external scripts, exfiltrate data, or manipulate DOM without any browser-level mitigation. (CWE-693) Violated: [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | helmet.noSniff(), helmet.frameguard() | [M-014](#m-014) |
| <a id="t-019"></a>[T-019](#t-019) | REST API | Tampering | No CSRF protection — no `csurf`, no SameSite cookie attribute — `server.ts` (no CSRF middleware). State-changing actions can be triggered cross-site: purchase orders, password changes, wallet transfers. (CWE-352) Violated: [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT Bearer token (partial CSRF mitigation) | [M-014](#m-014) |
| <a id="t-020"></a>[T-020](#t-020) | Admin Panel | Information Disclosure | `GET /rest/admin/application-configuration` returns full config object unauthenticated — [`routes/appConfiguration.ts:10`](vscode://file/home/mrohr/juice-shop/routes/appConfiguration.ts:10). Exposes Google OAuth client ID, server base URL, chatbot config, security.txt details. (CWE-200) Violated: [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-015](#m-015) |
| <a id="t-021"></a>[T-021](#t-021) | Admin Panel | Elevation of Privilege | `POST /api/Users` finale-rest endpoint — mass assignment allows setting `role: 'admin'` during registration (`server.ts:508`). Sequelize validates the role value is in allowlist but does not prevent the field from being set by the client. (CWE-915) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Role value validated (but field settable) | [M-015](#m-015) |
| <a id="t-022"></a>[T-022](#t-022) | Auth Service | Repudiation | Winston logger uses `format.simple()` not JSON — [`lib/logger.ts:8`](vscode://file/home/mrohr/juice-shop/lib/logger.ts:8). Security events (login success/failure, password reset) not explicitly logged. Cannot reconstruct who performed admin actions or when. (CWE-778) Violated: [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [LM-002](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Morgan access log + Winston console | [M-016](#m-016) |
| <a id="t-023"></a>[T-023](#t-023) | Admin Panel | Information Disclosure | Access log files publicly downloadable at `GET /support/logs/:file` — `server.ts:267`. Morgan `combined` format logs Authorization header values (JWT tokens) and full request URIs. Attacker can harvest valid JWT tokens from logs. (CWE-532) Violated: [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-009](#m-009) |
| <a id="t-024"></a>[T-024](#t-024) | Auth Service | Elevation of Privilege | No standard OIDC/SSO provider — custom JWT auth with no MFA enforcement — [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts). TOTP optional only. Architectural violation: no centralized session revocation, no MFA by default, no enterprise federation. (CWE-308) Violated: [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Optional TOTP 2FA present | [M-017](#m-017) |
| <a id="t-025"></a>[T-025](#t-025) | REST API | Tampering | No `package-lock.json`, no `npm audit` in CI — `package.json` (no lockfile at root). Vulnerable dependencies: express-jwt 0.1.3, jsonwebtoken 0.4.0, sanitize-html 1.4.2, unzipper 0.9.15. Supply chain attack or typosquat installs malicious version. (CWE-1104) Violated: [SC-001](https://owasp.org/www-project-dependency-check/), [SC-002](https://owasp.org/www-project-dependency-check/) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | CodeQL SAST; ZAP DAST | [M-018](#m-018) |
| <a id="t-026"></a>[T-026](#t-026) | File Upload Service | Tampering | ZIP upload in `handleZipFileUpload` ([`routes/fileUpload.ts:35`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:35)) uses `unzipper 0.9.15` (known path traversal CVE). Attacker crafts malicious ZIP with `../` path entries to write files outside `uploads/complaints/`, potentially overwriting app files. (CWE-22) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Path resolution check (may be bypassable) | [M-018](#m-018) |
| <a id="t-027"></a>[T-027](#t-027) | File Upload Service | Spoofing | Profile image URL upload SSRF ([`routes/profileImageUrlUpload.ts:26`](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:26)) — no URL validation before fetch. Attacker sets `imageUrl` to `http://169.254.169.254/latest/meta-data/` to probe cloud metadata, internal services, or localhost. (CWE-918) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Authentication required | [M-010](#m-010) |
| <a id="t-028"></a>[T-028](#t-028) | REST API | Tampering | Chatbot `POST /rest/chatbot/respond` processes user query against `juicy-chat-bot` — [`routes/chatbot.ts:105`](vscode://file/home/mrohr/juice-shop/routes/chatbot.ts:105). No prompt injection prevention. Training data can be loaded from external URL via config. Attacker may manipulate chatbot responses to exfiltrate user data or serve malicious content. (CWE-77) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT auth required | [M-019](#m-019) |
| <a id="t-029"></a>[T-029](#t-029) | Auth Service | Denial of Service | No rate limiting on `POST /rest/user/login` — `server.ts:594`. Attacker brute-forces credentials unrestricted. Combined with MD5 password hashing (fast to verify), even complex passwords can be tested millions of times per second. (CWE-307) Violated: [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None on login endpoint | [M-020](#m-020) |
| <a id="t-030"></a>[T-030](#t-030) | Admin Panel | Repudiation | Admin actions not audited — user management, order status, delivery toggles have no structured audit log (`server.ts:604+`). Cannot determine who deleted users, changed order status, or accessed admin config from Morgan access logs alone. (CWE-778) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Morgan access log | [M-016](#m-016) |

---

## 9. Critical Findings

The following findings require immediate attention due to their critical risk rating. Each finding links to its recommended mitigation in the [Mitigation Register](#10-mitigation-register).

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-001 — SQL Injection Authentication Bypass

**Scenario:** `POST /rest/user/login` executes raw SQL: `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '...'` at [`routes/login.ts:35`](vscode://file/home/mrohr/juice-shop/routes/login.ts:35). An unauthenticated attacker sends `email: "' OR 1=1--"` to match the first user row (typically admin), obtaining a fully-privileged JWT without any credentials.

**Current state:** No parameterized query used; MD5 hashing applied but email field fully injectable; no rate limiting. Evidence: [`routes/login.ts:35`](vscode://file/home/mrohr/juice-shop/routes/login.ts:35).

**Violated Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries

→ **Mitigation:** [M-001 — Replace Raw SQL with ORM Parameterized Queries](#m-001)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-002 — Hardcoded RSA Private Key Enables JWT Forgery

**Scenario:** The RSA private key used to sign all JWT authentication tokens is hardcoded as a string literal in [`lib/insecurity.ts:22`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:22). Since the repository is public on GitHub, any attacker can extract this key and use it to sign a JWT with `role: "admin"`, gaining full administrative access to the application.

**Current state:** Private key present as inline string literal in source. [`lib/insecurity.ts:22`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:22) (`-----BEGIN RSA PRIVATE KEY-----\r\nMIICA...` — redacted). All issued tokens are effectively forgeable.

**Violated Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets in dedicated secret manager

→ **Mitigation:** [M-002 — Remove Hardcoded Secrets; Load from Environment](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-003 — MD5 Password Hashing Enables Mass Credential Compromise

**Scenario:** All user passwords are stored as MD5 hashes via `crypto.createHash('md5')` — [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43). MD5 is not a password hashing function — it has no salt, is extremely fast (billions per second on GPU), and is fully covered by rainbow tables. Any database extraction (via T-001 or T-005) immediately yields crackable hashes.

**Current state:** `hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')` — [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43). No salt, no iterations. Production user accounts vulnerable.

**Violated Requirements:** [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Delegate password storage to IdP

→ **Mitigation:** [M-003 — Replace MD5 with bcrypt for Password Hashing](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-004 — XXE File Disclosure via XML Upload

**Scenario:** `POST /file-upload` processes XML with `libxml.parseXml(data, { noent: true })` — [`routes/fileUpload.ts:83`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83). The `noent: true` option enables external entity resolution. An attacker uploads XML containing `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and the file's contents are returned in the error message body.

**Current state:** `noent: true` is explicitly set in the libxmljs2 parse call. Error response includes `utils.trunc(xmlString, 400)` — parsed content in response body. `routes/fileUpload.ts:83,89`.

**Violated Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — Harden XML parsers against XXE

→ **Mitigation:** [M-004 — Disable XXE in XML Parser](#m-004)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-005 — SQL Injection in Product Search Dumps Full Database

**Scenario:** `GET /rest/products/search?q=` builds raw SQL: `` SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) `` — [`routes/search.ts:21`](vscode://file/home/mrohr/juice-shop/routes/search.ts:21). A UNION SELECT payload extracts the entire `Users` table including email addresses and MD5 password hashes.

**Current state:** No parameterized query; 200-char truncation insufficient to prevent UNION injection. Endpoint unauthenticated. [`routes/search.ts:21`](vscode://file/home/mrohr/juice-shop/routes/search.ts:21).

**Violated Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries

→ **Mitigation:** [M-001 — Replace Raw SQL with ORM Parameterized Queries](#m-001)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-021 — Mass Assignment Enables Admin Privilege Escalation

**Scenario:** `POST /api/Users` uses finale-rest auto-generated endpoint that passes all request body fields to Sequelize `User.create()`. An attacker sends `{ email, password, role: "admin" }` during registration. Sequelize validates that `"admin"` is in the role allowlist — but does not prevent the field from being set client-side.

**Current state:** [`models/user.ts:92`](vscode://file/home/mrohr/juice-shop/models/user.ts:92) — role field validates values in `['customer', 'deluxe', 'accounting', 'admin']` but is settable by anyone. `server.ts:508` — finale auto-generated endpoint used.

→ **Mitigation:** [M-015 — Restrict Admin Endpoints and Fix Mass Assignment](#m-015)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-006 — Remote Code Execution via B2B Order eval

**Scenario:** `POST /b2b/v2/orders` evaluates `orderLinesData` via `vm.runInContext('safeEval(orderLinesData)', sandbox)` at [`routes/b2bOrder.ts:22`](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:22). The notevil sandbox is escapable — an authenticated attacker can execute arbitrary Node.js code on the server, enabling file read, network calls, and process spawning.

**Current state:** `vm.createContext` + `vm.runInContext` + `safeEval` in active use. notevil sandbox bypass is a known issue. JWT auth required but easily obtained via T-001. `routes/b2bOrder.ts:22`.

→ **Mitigation:** [M-005 — Remove eval from B2B Order Processing](#m-005)

---

## 10. Mitigation Register

Prioritized measures to address identified threats. Each mitigation references the threats it addresses and includes concrete implementation guidance.

### <a id="m-001"></a>M-001 · Replace Raw SQL with ORM Parameterized Queries

**Addresses:** [T-001](#t-001) · [T-005](#t-005)
**Fulfills Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** SQL injection in the login and product search routes allows authentication bypass and full database extraction. Fixing this eliminates the most critical unauthenticated attack vector.

**How:**
1. In [`routes/login.ts:35`](vscode://file/home/mrohr/juice-shop/routes/login.ts:35), replace raw Sequelize `.query()` with ORM `findOne`:
2. In [`routes/search.ts:21`](vscode://file/home/mrohr/juice-shop/routes/search.ts:21), replace raw `.query()` with Sequelize `Op.like` operator:
3. Never interpolate user input into SQL strings; always use ORM methods or parameterized queries

```typescript
// Before — routes/login.ts:35
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })

// After
UserModel.findOne({
  where: {
    email: req.body.email || '',
    password: security.hash(req.body.password || ''),
    deletedAt: null
  }
})

// Before — routes/search.ts:21
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

// After
ProductModel.findAll({
  where: {
    [Op.and]: [
      { deletedAt: null },
      { [Op.or]: [
        { name: { [Op.like]: `%${criteria}%` } },
        { description: { [Op.like]: `%${criteria}%` } }
      ]}
    ]
  },
  order: [['name', 'ASC']]
})
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

---

### <a id="m-002"></a>M-002 · Remove Hardcoded Secrets; Load from Environment

**Addresses:** [T-002](#t-002) · [T-007](#t-007)
**Fulfills Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** The RSA private key hardcoded in source enables any attacker to forge admin JWTs. Rotating the key and loading it from the environment eliminates the forgery vector and limits blast radius if source code is exposed.

**How:**
1. Generate a new RSA key pair: `openssl genrsa -out jwt_private.pem 2048 && openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem`
2. Remove the hardcoded `privateKey` and `publicKey` literals from `lib/insecurity.ts:21-22`
3. Load from environment at startup: `const privateKey = process.env.JWT_PRIVATE_KEY || fs.readFileSync('/run/secrets/jwt_private', 'utf8')`
4. Move HMAC secret to `process.env.HMAC_SECRET`; move cookie secret to `process.env.COOKIE_SECRET`
5. Validate all secrets are set at startup (throw if missing in production)
6. In Docker: mount secrets as read-only files; in Kubernetes: use Secret volumes

```typescript
// Before — lib/insecurity.ts:21-22
export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICA...'

// After
const privateKey = process.env.JWT_PRIVATE_KEY ??
  (process.env.JWT_PRIVATE_KEY_FILE ? fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE, 'utf8') : null)
if (!privateKey) throw new Error('JWT_PRIVATE_KEY not configured')
export const publicKey = process.env.JWT_PUBLIC_KEY ?? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')
export const hmacSecret = process.env.HMAC_SECRET ?? (() => { throw new Error('HMAC_SECRET not configured') })()
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

---

### <a id="m-003"></a>M-003 · Replace MD5 with bcrypt for Password Hashing

**Addresses:** [T-003](#t-003)
**Fulfills Requirements:** [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** MD5 hashes are trivially crackable via GPU or rainbow tables. bcrypt's intentional slowness (cost factor 12 ≈ 300ms/hash) makes brute-force attacks computationally infeasible.

**How:**
1. Install: `npm install bcrypt && npm install --save-dev @types/bcrypt`
2. Replace `security.hash()` in [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) and all callers
3. Update [`models/user.ts:75`](vscode://file/home/mrohr/juice-shop/models/user.ts:75) password setter to use async bcrypt
4. Update login query: since bcrypt compare is async, use `UserModel.findOne({ where: { email } })` then verify hash separately
5. Write a migration script to re-hash existing MD5 passwords on next login (detect MD5 by length = 32 chars)

```typescript
// Before — lib/insecurity.ts:43
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After
import bcrypt from 'bcrypt'
const BCRYPT_ROUNDS = 12
export const hashPassword = async (password: string): Promise<string> =>
  bcrypt.hash(password, BCRYPT_ROUNDS)
export const comparePassword = async (plain: string, hashed: string): Promise<boolean> =>
  bcrypt.compare(plain, hashed)
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

### <a id="m-004"></a>M-004 · Disable XXE in XML Parser

**Addresses:** [T-004](#t-004)
**Fulfills Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** One configuration flag change eliminates file disclosure and SSRF via the XML upload endpoint. The current `noent: true` setting is the root cause.

**How:**
1. Change `noent: true` to `noent: false` in [`routes/fileUpload.ts:83`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)
2. Add `nonet: true` to also prevent network entity resolution
3. Consider rejecting XML upload entirely if no legitimate use case exists

```typescript
// Before — routes/fileUpload.ts:83
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })

// After
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, nocdata: true })', sandbox, { timeout: 2000 })
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

---

<!-- QA: M-005 addresses Critical threat T-006 — ensure Addresses line links back (already present) -->
### <a id="m-005"></a>M-005 · Remove eval from B2B Order Processing

**Addresses:** [T-006](#t-006)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** Server-side code evaluation of user-controlled input creates RCE risk regardless of sandbox. No sandbox has a perfect escape prevention record.

**How:**
1. Remove `vm.createContext`, `vm.runInContext`, and `safeEval` from [`routes/b2bOrder.ts`](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts)
2. Define a strict JSON schema for `orderLinesData` using Zod or Joi
3. Parse and validate the schema; reject any non-conforming input with HTTP 400

```typescript
// Before — routes/b2bOrder.ts:21-27
const sandbox = { safeEval, orderLinesData }
vm.createContext(sandbox)
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// After
import { z } from 'zod'
const OrderLineSchema = z.array(z.object({
  productId: z.number().int().positive(),
  quantity: z.number().int().min(1).max(100)
}))
const parsed = OrderLineSchema.safeParse(JSON.parse(orderLinesData))
if (!parsed.success) return res.status(400).json({ error: 'Invalid order data' })
```

**Reference:** CWE-94

---

### <a id="m-006"></a>M-006 · Sanitize NoSQL Query Inputs

**Addresses:** [T-008](#t-008) · [T-009](#t-009)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** NoSQL injection via `$where` and unsanitized `_id` fields allows cross-user data access and mass data manipulation.

**How:**
1. In [`routes/updateProductReviews.ts:18`](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:18): validate `req.body.id` is a string, not an object; remove `{ multi: true }` option
2. In [`routes/trackOrder.ts:18`](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:18): replace `$where` with direct field comparison `{ orderId: id }` after sanitizing `id` to alphanumeric only
3. Use `typeof id === 'string'` check before query execution

```typescript
// Before — routes/updateProductReviews.ts:18
db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })

// After
if (typeof req.body.id !== 'string' || !/^[a-zA-Z0-9]+$/.test(req.body.id)) {
  return res.status(400).json({ error: 'Invalid review ID' })
}
db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } })

// Before — routes/trackOrder.ts:18
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })

// After
db.ordersCollection.find({ orderId: String(id).replace(/[^\w-]/g, '') })
```

**Reference:** CWE-943

---

### <a id="m-007"></a>M-007 · Configure CORS with Explicit Origin Allowlist

**Addresses:** [T-010](#t-010)
**Fulfills Requirements:** [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Wildcard CORS eliminates the browser's same-origin protection for all authenticated users.

**How:**
1. Replace `app.use(cors())` with a configured CORS instance
2. Specify the actual frontend origin(s) in the allowlist

```typescript
// Before — server.ts:181-182
app.options('*', cors())
app.use(cors())

// After
const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS ?? 'http://localhost:4200').split(',')
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true)
    else callback(new Error(`Origin ${origin} not allowed`))
  },
  credentials: true
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html

---

### <a id="m-008"></a>M-008 · Replace errorhandler() with Safe Custom Error Handler

**Addresses:** [T-011](#t-011)
**Fulfills Requirements:** [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Stack trace disclosure in HTTP responses reveals file paths, library versions, and application internals that aid attacker reconnaissance.

**How:**
1. Remove `errorhandler()` middleware from `server.ts:676`
2. Add a custom error handler that logs full details server-side but returns generic messages to clients

```typescript
// Before — server.ts:676
app.use(errorhandler())

// After
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error({ message: err.message, stack: err.stack, path: req.path, method: req.method })
  const statusCode = (res.statusCode && res.statusCode !== 200) ? res.statusCode : 500
  res.status(statusCode).json({ error: 'An unexpected error occurred' })
})
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

---

### <a id="m-009"></a>M-009 · Restrict Public File and Metrics Endpoints

**Addresses:** [T-012](#t-012) · [T-014](#t-014) · [T-023](#t-023)
**Fulfills Requirements:** [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** FTP directory, log files, and Prometheus metrics are all publicly accessible, leaking credentials, tokens, and operational data.

**How:**
1. Remove `serve-index` for `/ftp`, `/support/logs`, and `/encryptionkeys`; or add authentication middleware before them
2. Protect `/metrics` with bearer token or IP allowlist: `app.get('/metrics', ipFilter(['127.0.0.1', '10.0.0.0/8'], { mode: 'allow' }), metrics.serveMetrics())`
3. Move sensitive FTP files out of the web-accessible directory
4. Configure Morgan to exclude `Authorization` header from log format

**Reference:** CWE-548

---

### <a id="m-010"></a>M-010 · Add URL Validation Before Server-Side Fetch (SSRF Fix)

**Addresses:** [T-013](#t-013) · [T-027](#t-027)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Unrestricted server-side URL fetching enables SSRF attacks against internal network services including cloud metadata endpoints.

**How:**
1. Validate the URL scheme is `https://` only
2. Resolve the DNS hostname and verify the IP is not RFC 1918, loopback, or link-local
3. Validate the Content-Type of the response is `image/*`

```typescript
import { Resolver } from 'node:dns/promises'
async function isSafeUrl(url: string): Promise<boolean> {
  const parsed = new URL(url)
  if (parsed.protocol !== 'https:') return false
  const resolver = new Resolver()
  const [ip] = await resolver.resolve4(parsed.hostname)
  const privateRanges = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./, /^169\.254\./]
  return !privateRanges.some(r => r.test(ip))
}
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

### <a id="m-011"></a>M-011 · Replace Open Redirect with Server-Side Redirect Map

**Addresses:** [T-015](#t-015)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Open redirects enable phishing by allowing attackers to craft URLs that appear legitimate but redirect to attacker-controlled sites.

**How:**
1. Define a server-side map of allowed redirect codes to URLs
2. Accept only a `code` parameter; look up the destination server-side
3. Return HTTP 400 for unknown codes; never redirect to user-supplied full URLs

**Reference:** CWE-601

---

### <a id="m-012"></a>M-012 · Migrate JWT from localStorage to HttpOnly Cookie via BFF Pattern

**Addresses:** [T-016](#t-016)
**Fulfills Requirements:** [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html), [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** High

**Why:** JWT in localStorage is accessible to any JavaScript on the page — a single XSS vulnerability anywhere results in all active sessions being compromised. HttpOnly cookies are inaccessible to JavaScript.

**How:**
1. Implement a BFF session endpoint on the server (`/bff/session`)
2. On login success, set: `res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 6 * 3600 * 1000 })`
3. Remove `localStorage.setItem('token', ...)` from Angular login service
4. Update `RequestInterceptor` to not set `Authorization` header from localStorage — cookie is sent automatically
5. Remove `localStorage.setItem('email', ...)` and `X-User-Email` header; derive email from server-side session

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

---

### <a id="m-013"></a>M-013 · Remove bypassSecurityTrustHtml; Use DOMPurify for User Content

**Addresses:** [T-017](#t-017)
**Fulfills Requirements:** [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** `bypassSecurityTrustHtml` disables Angular's built-in XSS sanitization. Stored XSS via feedback, IP headers, or email fields enables token theft from the admin panel.

**How:**
1. Install DOMPurify: `npm install dompurify && npm install --save-dev @types/dompurify`
2. In `about.component.ts:119`, `last-login-ip.component.ts:39`, `administration.component.ts:60`: sanitize with DOMPurify before calling `bypassSecurityTrustHtml`, or better, use Angular's `{{ }}` interpolation for plain text fields
3. Update `sanitize-html` from `1.4.2` to `^2.x` on the server side

```typescript
// Before — about.component.ts:119
feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(feedbacks[i].comment)

// After
import DOMPurify from 'dompurify'
feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(
  DOMPurify.sanitize(feedbacks[i].comment, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] })
)
// Or use plain text interpolation: <td>{{ feedback.comment }}</td>
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

### <a id="m-014"></a>M-014 · Add CSP, HSTS, and CSRF Protection Headers

**Addresses:** [T-018](#t-018) · [T-019](#t-019)
**Fulfills Requirements:** [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Absence of CSP makes all XSS exploits unrestricted. Absence of HSTS allows downgrade attacks. Absence of CSRF protection allows cross-site state changes.

**How:**
1. Enable `helmet.contentSecurityPolicy()` with restrictive directives
2. Enable `helmet.hsts({ maxAge: 31536000, includeSubDomains: true })`
3. Enable `helmet.referrerPolicy({ policy: 'same-origin' })`
4. Set `SameSite=Lax` on session cookies (requires M-012 first for HttpOnly cookies)

```typescript
// Add to server.ts after helmet.noSniff() and frameguard():
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],  // refine further after testing
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"]
  }
}))
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))
app.use(helmet.referrerPolicy({ policy: 'same-origin' }))
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

---

### <a id="m-015"></a>M-015 · Restrict Admin Endpoints and Fix Mass Assignment

**Addresses:** [T-020](#t-020) · [T-021](#t-021)
**Fulfills Requirements:** [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html), [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Unprotected admin config endpoint leaks OAuth credentials. Mass assignment via user registration enables privilege escalation to admin.

**How:**
1. Add `security.isAuthorized()` and admin role check to `/rest/admin/application-configuration` and `/rest/admin/application-version`
2. In [`routes/appConfiguration.ts`](vscode://file/home/mrohr/juice-shop/routes/appConfiguration.ts), filter the config to a safe subset before returning
3. Override the finale `create` handler for Users to strip the `role` field from the request body

```typescript
// Fix mass assignment — add before finale.initialize():
app.post('/api/Users', (req, res, next) => {
  delete req.body.role    // never allow client to set role
  delete req.body.isAdmin
  delete req.body.totpSecret
  next()
})

// Protect admin endpoints:
app.get('/rest/admin/application-configuration', security.isAuthorized(), security.isAdmin(), retrieveAppConfiguration())
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

---

### <a id="m-016"></a>M-016 · Implement Structured Security Event Logging

**Addresses:** [T-022](#t-022) · [T-030](#t-030)
**Fulfills Requirements:** [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [LM-002](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Without structured security event logging, incident response is severely hampered — impossible to reconstruct the sequence of an attack or identify compromised accounts.

**How:**
1. Configure Winston with JSON format: `format: winston.format.json()`
2. Add explicit log calls for: login success/failure with user ID and IP, password changes, privilege changes, admin actions
3. Never log passwords, tokens, or PII in log messages

```typescript
// lib/logger.ts
export default winston.createLogger({
  transports: [new winston.transports.Console()],
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  )
})
// In routes/login.ts, log events:
logger.info({ event: 'LOGIN_SUCCESS', userId: user.data.id, email: user.data.email, ip: req.ip })
logger.warn({ event: 'LOGIN_FAILURE', email: req.body.email, ip: req.ip })
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

---

### <a id="m-017"></a>M-017 · Enforce MFA; Consider Standard OIDC Provider

**Addresses:** [T-024](#t-024)
**Fulfills Requirements:** [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** High

**Why:** Optional TOTP provides no security guarantee — users with sensitive roles skip it. Centralized auth with mandatory MFA is the OWASP-recommended architectural pattern.

**How:**
1. Require TOTP enrollment for all `admin` and `accounting` role users at first login
2. Longer term: integrate a standard OIDC provider (e.g., Keycloak, Auth0) and replace custom JWT auth
3. Enforce MFA at the IdP level so it cannot be bypassed at the application layer

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

---

### <a id="m-018"></a>M-018 · Add Lockfile, SCA Scanning, and Update Vulnerable Dependencies

**Addresses:** [T-025](#t-025) · [T-026](#t-026)
**Fulfills Requirements:** [SC-001](https://owasp.org/www-project-dependency-check/), [SC-002](https://owasp.org/www-project-dependency-check/)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Missing lockfile enables supply-chain attacks (dependency confusion, typosquatting). Outdated packages (express-jwt 0.1.3, jsonwebtoken 0.4.0, unzipper 0.9.15) have known CVEs.

**How:**
1. Run `npm install` and commit the generated `package-lock.json`
2. Update critical packages: `npm install express-jwt@^8 jsonwebtoken@^9 sanitize-html@^2 unzipper@^0.12`
3. Add `npm audit --audit-level=high` step to `ci.yml` jobs
4. Pin base Docker image to digest: `FROM node:24@sha256:<digest> AS installer`
5. Pin CodeQL actions to SHA: replace `github/codeql-action/init@v3` with SHA-pinned version

```yaml
# Add to .github/workflows/ci.yml test job:
- name: "Run security audit"
  run: npm audit --audit-level=high
```

**Reference:** https://owasp.org/www-project-dependency-check/

---

### <a id="m-019"></a>M-019 · Add Prompt Injection Protection to Chatbot

**Addresses:** [T-028](#t-028)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Chatbot query injection can manipulate responses, exfiltrate conversation context, or serve malicious content to users.

**How:**
1. Validate and sanitize `req.body.query` — strip HTML, limit length, reject known injection patterns
2. Validate training data URL at startup against an allowlist
3. Validate chatbot response before returning to client (strip any HTML/script content)

**Reference:** CWE-77

---

### <a id="m-020"></a>M-020 · Add Rate Limiting to Login Endpoint

**Addresses:** [T-029](#t-029)
**Fulfills Requirements:** [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Unrestricted login endpoint enables brute-force attacks. Combined with MD5 password hashing (extremely fast to verify), even long passwords can be tested at millions of attempts per second.

**How:**
1. Add a `rateLimit` instance before the login handler
2. Use a stricter limit than reset-password (10 attempts per 15 min per IP is standard)
3. Consider account lockout or CAPTCHA after 5 consecutive failures

```typescript
// Before — server.ts:594
app.post('/rest/user/login', login())

// After
app.post('/rest/user/login',
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Too many login attempts' }),
  login()
)
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

---

## 11. Out of Scope

Areas deliberately excluded from this assessment, including accepted risks and items requiring separate analysis.

- **Intentional vulnerability challenges:** OWASP Juice Shop is designed to contain ~100 security challenges. Many vulnerabilities are intentional (e.g., `/ftp/` exposure, SQL injection, XSS in review fields) and exist for educational purposes. This assessment documents them as real vulnerabilities while acknowledging their intentional nature.
- **Third-party dependencies CVE analysis:** Full SCA scan not performed (`WITH_SCA=false`). Package versions were noted (express-jwt 0.1.3, jsonwebtoken 0.4.0) but no automated CVE database lookup was conducted.
- **Frontend Angular template XSS audit:** Only `bypassSecurityTrustHtml` usages were checked; a full audit of all template bindings and DOM sinks was not performed.
- **Network infrastructure:** No firewall rules, load balancer configuration, or cloud provider security groups were available for review.
- **Google OAuth implementation details:** The OAuth flow implementation in [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) uses a custom approach; a full OAuth security audit (redirect URI validation, PKCE enforcement, state parameter) was not conducted.
- **WebSocket security:** Socket.io events and handlers were not analyzed for injection or authentication bypass.
- **Crypto challenge components:** [`routes/web3Wallet.ts`](vscode://file/home/mrohr/juice-shop/routes/web3Wallet.ts), NFT minting, and blockchain integration were not analyzed in depth.
- **Performance-based DoS:** Application-level resource exhaustion (YAML bomb in fileUpload is documented; deep analysis of other DoS vectors not performed).
