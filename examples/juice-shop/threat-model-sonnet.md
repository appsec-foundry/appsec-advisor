# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-07T00:00:00Z |
| Analysis Duration | n/a (inline analysis) |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Agent Models | all agents: claude-sonnet-4-6 |
| Input Tokens | unavailable |
| Output Tokens | unavailable |
| Cache Read Tokens | unavailable |
| Cache Write Tokens | unavailable |
| Estimated Cost | unavailable |
| Context Sources | None |
| Repo URL | https://github.com/juice-shop/juice-shop |
| Team Owner | OWASP / Community Contributors |
| Compliance Scope | None specified |
| Mode | Full assessment |

> ℹ Token and cost data are not accessible at agent runtime. Check the Anthropic Console for usage details of this session.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Containers (Technology Architecture)](#22-containers-technology-architecture)
   - [2.3 Security Architecture Assessment](#23-security-architecture-assessment)
3. [Security-Relevant Use Cases](#3-security-relevant-use-cases)
4. [Assets](#4-assets)
5. [Attack Surface](#5-attack-surface)
6. [Trust Boundaries](#6-trust-boundaries)
7. [Identified Security Controls](#7-identified-security-controls)
8. [Threat Register](#8-threat-register)
9. [Critical Findings](#9-critical-findings)
10. [Mitigation Register](#10-mitigation-register)
11. [Out of Scope](#11-out-of-scope)

---

## 1. System Overview

OWASP Juice Shop (version 19.2.1) is a **deliberately insecure** web application created by the Open Worldwide Application Security Project (OWASP) as a training, awareness, demonstration, and capture-the-flag (CTF) platform. The application simulates a realistic e-commerce juice shop and contains an extensive catalog of intentional security vulnerabilities spanning all OWASP Top 10 categories and many more.

**Important caveat:** This threat model analyzes the codebase as-if it were a real production application. Every "vulnerability" documented here is intentional by design. This analysis is provided for educational and training purposes, and to demonstrate what a real-world threat model for a Node.js/Angular e-commerce application would surface.

**Complexity tier selected: Moderate** — The system has a clear SPA frontend, a REST API backend, two data stores (SQLite + in-memory MarsDB), file storage, and a chatbot subsystem, but is deployed as a single container without microservice decomposition.

### Business Context

The system handles:
- User registration, authentication (JWT-based), and profile management
- Product catalog browsing and search
- Shopping basket and order placement
- Payment method management (credit cards) and digital wallet
- File uploads (complaints, profile images)
- B2B order processing API
- Web3/NFT integration endpoints
- A challenge/CTF engine tracking solved security puzzles
- A rule-based chatbot (juicy-chat-bot)

### Deployment Context

The application is containerized via Docker using a distroless `gcr.io/distroless/nodejs24-debian13` runtime image. It runs as UID 65532 (non-root). The application listens on port 3000 with no reverse proxy, WAF, or API gateway in the default configuration. SQLite is used as the primary relational database, stored as a file at `data/juiceshop.sqlite`. An in-memory MarsDB instance handles product reviews and orders.

### Overall Security Impression

The codebase contains numerous confirmed critical vulnerabilities including SQL injection in authentication and search, hardcoded RSA private key, CORS configured to allow all origins, missing CSP, JWT tokens stored in localStorage (XSS accessible), server-side template injection via Pug, and remote code execution via the B2B order endpoint. These are all intentional training vulnerabilities, but a real application with this profile would be immediately compromisable.

---

## 2. Architecture Diagrams

### 2.1 System Context

```mermaid
graph TD
    subgraph INTERNET["🌐 Public Internet · untrusted"]
        USER["Regular User\nWeb Browser\nAngular 17 SPA\non-prem / browser"]
        ADMIN["Admin User\nWeb Browser\nAngular 17 SPA\non-prem / browser"]
        B2B["B2B Client\nExternal System\nHTTP Client\non-prem / unknown"]
        ATTACKER["Attacker\nWeb Browser / Script\non-prem / internet"]:::risk
    end

    subgraph HOSTED["🔒 Application Host · Docker Container"]
        SHOP["OWASP Juice Shop\nExpress 4.22 + Angular 17\nNode.js 24\nDocker · distroless"]
    end

    subgraph EXTERNAL["External Services · untrusted"]
        GOOGLE["Google OAuth 2.0\naccounts.google.com\nHTTPS"]
        NFT["Ethereum/Web3\nBlockchain APIs\nHTTPS"]
    end

    USER -->|"HTTPS GET/POST · port 3000"| SHOP
    ADMIN -->|"HTTPS GET/POST · port 3000 (admin routes)"| SHOP
    B2B -->|"POST /b2b/v2/orders · JWT auth"| SHOP
    ATTACKER -->|"HTTPS · exploit attempts"| SHOP:::risk
    SHOP -->|"OAuth2 implicit token exchange"| GOOGLE
    SHOP -->|"Web3 RPC calls"| NFT

%% Trust Boundary Key:
%% 🌐 Public Internet → 🔒 Application Host: No WAF/CDN; direct TCP 3000
%% 🔒 Application Host → External Services: HTTPS outbound; no egress filtering
```

### 2.2 Containers (Technology Architecture)

```mermaid
graph TD
    subgraph INTERNET["🌐 Public Internet · untrusted"]
        BROWSER["Browser Client\nAngular 17 SPA\nNode 20 build · Nginx none\nServed from Express static"]
    end

    subgraph CONTAINER["🔒 Docker Container · gcr.io/distroless/nodejs24\nUID 65532 · port 3000"]
        EXPRESS["REST API Server\nExpress 4.22 + TypeScript\nNode.js 24\nDocker · distroless"]:::risk
        AUTH["Auth Module\nJWT RS256 (jsonwebtoken 0.4.0)\nexpress-jwt 0.1.3\nIn-process lib"]:::risk
        CHATBOT["Chatbot Service\njuicy-chat-bot 0.9\nRule-based NLP\nIn-process module"]
        FILEHANDLER["File Handler\nmulter 1.4.5-lts\nXML/ZIP/YAML processing\nIn-process module"]:::risk
        STATIC["Static File Server\nExpress static\nftp/ encryptionkeys/ logs/\nIn-process"]:::risk
    end

    subgraph DATA["🔐 Data Tier · restricted"]
        SQLITE[("SQLite DB\nSequelize 6.37\ndata/juiceshop.sqlite\nLocal file storage")]
        MARSDB[("In-Memory DB\nMarsDB 0.6\nReviews + Orders\nIn-process memory")]
        FILESYSTEM["File System\nUploads + FTP dir\nftp/ uploads/ logs/\nContainer filesystem"]:::risk
    end

    subgraph EXTERNAL["External · untrusted"]
        GOOGLE_OAUTH["Google OAuth\nImplicit Flow\nHTTPS"]
        PROMETHEUS["Prometheus Metrics\n/metrics endpoint\nNo auth required"]:::risk
    end

    BROWSER -->|"GET / (SPA bootstrap · unauthenticated)"| EXPRESS
    BROWSER -->|"POST /rest/user/login · plain HTTP"| AUTH
    BROWSER -->|"GET /rest/products/search?q= · unauthenticated"| EXPRESS
    BROWSER -->|"POST /file-upload · multipart"| FILEHANDLER
    BROWSER -->|"GET /ftp/:file · unauthenticated"| STATIC
    BROWSER -->|"GET /metrics · unauthenticated"| PROMETHEUS
    EXPRESS -->|"SQL queries · Sequelize ORM / raw SQL"| SQLITE
    EXPRESS -->|"NoSQL queries"| MARSDB
    FILEHANDLER -->|"Write · complaint uploads"| FILESYSTEM
    STATIC -->|"Read · serve files"| FILESYSTEM
    AUTH -->|"OAuth implicit token exchange"| GOOGLE_OAUTH
    EXPRESS -->|"JWT sign/verify · RS256"| AUTH

%% Trust Boundary Key:
%% 🌐 Public Internet → 🔒 Container: No firewall/WAF; direct port 3000
%% 🔒 Container → 🔐 Data Tier: Same process/filesystem; no network isolation
%% Auth enforced per-route by express-jwt middleware (not at edge)
```

### 2.3 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ❌ | No gateway; Express routes exposed directly on port 3000 |
| BFF (Backend for Frontend) | ❌ | SPA calls backend directly; JWT stored in localStorage, not HttpOnly cookie |
| Defense-in-depth | ❌ | Single container; no WAF, no network segmentation, no edge auth |
| Separation of concerns | ⚠️ | Route handlers mix business logic and auth checks inline |
| Least privilege | ⚠️ | Container runs as UID 65532 (good); but CORS allows all origins (bad) |
| Secrets management | ❌ | RSA private key hardcoded in `lib/insecurity.ts:23`; HMAC key hardcoded at line 44 |
| Network segmentation | ❌ | DB, app, and file system in same container; no network policy |
| Secure defaults | ❌ | XSS filter commented out; CORS wildcard; no CSP; no rate limiting on login |

#### Trust Model Evaluation

The trust model has critical structural gaps:

- **No edge enforcement**: Traffic from the public internet reaches the Express application directly with no WAF, CDN, or reverse proxy. An attacker can probe all endpoints without any pre-screening.
- **Implicit trust within container**: The SQLite database file, the FTP directory, the encryption keys, and the application code all reside within the same container filesystem. Compromise of the Express process yields full access to all data.
- **Client-side trust boundaries**: Angular route guards (`AdminGuard`, `AccountingGuard`, `LoginGuard`) are the only mechanism preventing unauthorized access to the admin and accounting UI — these are trivially bypassed by directly calling API endpoints. The backend does enforce JWT checks on most REST routes, but not uniformly.
- **No server-to-server authentication**: The B2B API uses the same JWT scheme as end-users; there is no separate service credential system.

#### Authentication and Authorization Architecture

- **Authentication**: Custom JWT implementation using RS256 (`jsonwebtoken 0.4.0` — severely outdated). The private key is hardcoded in source. Token lifecycle: 6h expiry, no refresh token rotation, no revocation mechanism. Tokens stored in `localStorage` (XSS-accessible).
- **Google OAuth**: Implements the deprecated **implicit flow** (receives `access_token` in URL fragment, not authorization code + PKCE). The OAuth component derives password from email via `btoa(email.split('').reverse().join(''))` — a trivially reversible pseudorandom credential.
- **2FA**: TOTP-based 2FA is available but optional. 2FA token endpoint has a 100-req/5min rate limit.
- **Authorization**: Role-based (`customer`, `deluxe`, `accounting`, `admin`). Roles are embedded in the JWT payload and verified per-route in middleware. `security.isAuthorized()` uses `express-jwt` to verify the token. `security.isAccounting()` decodes and inspects the role claim. The `/api/Products/:id` PUT endpoint is intentionally left unprotected (line 369 of `server.ts`).

#### Key Architectural Risks

| # | Structural Risk | Impact if Exploited | Linked Threats |
|---|-----------------|--------------------|----|
| 1 | No centralized session invalidation — JWT-only auth with no server-side revocation list | Stolen tokens valid for full 6h window even after logout | T-001, T-002 |
| 2 | Single container co-locates application code, keys, database, and file storage | Full data compromise from single code execution vulnerability | T-003, T-016 |
| 3 | No edge security layer — no WAF, rate limiting (login), or DDoS mitigation at infrastructure level | Automated attacks (credential stuffing, scraping) face no throttling | T-005, T-006 |
| 4 | Deprecated OAuth implicit flow with client-side token handling | Access tokens in URL → leaked to logs, Referer headers, browser history | T-015 |
| 5 | File system fully accessible from web routes — `/ftp`, `/encryptionkeys`, `/support/logs` served with directory listing | Direct file download of sensitive data without authentication | T-019, T-020 |

#### Overall Architecture Security Rating

🔴 **Critical gaps** — The application has no defense-in-depth layers, a hardcoded cryptographic private key, wildcard CORS, no CSP, JWT tokens in localStorage, deprecated OAuth flow, unauthenticated access to sensitive directories, and multiple confirmed injection vulnerabilities (SQL, NoSQL, OS command via RCE). While intentional for training purposes, a production system with this architecture profile would be immediately and completely compromisable.

---

> ⚠ **QA:** Section 2.4 Technology Architecture diagram is missing. Consider adding a technology-stack-level architecture diagram showing component details, deployment platform, and framework versions.

## 3. Security-Relevant Use Cases

### 3.1 Authentication Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as Express API
    participant DB as SQLite DB
    participant SEC as security module

    U->>API: POST /rest/user/login {email, password}
    Note over API: No rate limit on this endpoint
    API->>DB: SELECT * FROM Users WHERE email='?' AND password=MD5('?')
    Note over DB: Raw SQL string interpolation - SQL injection possible
    DB-->>API: User row or null
    alt User found with totpSecret
        API-->>U: 401 {status: totp_token_required, tmpToken}
        U->>API: POST /rest/2fa/verify {tmpToken, totp}
        API-->>U: 200 {token, bid}
    else User found without 2FA
        API->>SEC: security.authorize(user)
        SEC-->>API: JWT RS256 signed, 6h expiry
        API-->>U: 200 {authentication: {token, bid, umail}}
        Note over U: Token stored in localStorage (XSS accessible)
    else Not found
        API-->>U: 401 Invalid email or password
    end
```

### 3.2 Authorization / Access Control

```mermaid
sequenceDiagram
    participant U as User Browser
    participant MW as Auth Middleware
    participant R as Route Handler
    participant DB as SQLite DB

    U->>MW: GET /rest/basket/42 [Authorization: Bearer JWT]
    MW->>MW: expressJwt verify(token, publicKey)
    alt Token invalid or missing
        MW-->>U: 401 Unauthorized
    else Token valid
        MW->>R: next() with req.user populated
        R->>R: Check req.user.bid vs requested basket ID
        Note over R: No IDOR check - any authenticated user\ncan request any basket ID
        R->>DB: SELECT * FROM Baskets WHERE id=42
        DB-->>R: Basket data
        R-->>U: 200 {status: success, data: basket}
    end
    U->>MW: GET /api/Users [Authorization: Bearer JWT]
    MW->>MW: expressJwt verify(token, publicKey)
    MW->>R: next()
    Note over R: No admin check - any authenticated user\ncan list all users via GET /api/Users
    R->>DB: SELECT * FROM Users
    DB-->>R: All user records
    R-->>U: 200 {data: [all users]}
```

### 3.3 Input Validation and SQL Injection

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as Express API
    participant DB as SQLite DB

    U->>API: GET /rest/products/search?q=apple'+UNION+SELECT...
    Note over API: No input sanitization or parameterized query
    API->>DB: SELECT * FROM Products WHERE name LIKE '%apple' UNION SELECT...%'
    Note over DB: Raw string interpolation - UNION injection possible
    DB-->>API: Products + injected data (user emails, passwords)
    API-->>U: 200 {data: [...product + user data...]}

    U->>API: POST /rest/user/login {email: "' OR 1=1--", password: "x"}
    API->>DB: SELECT * FROM Users WHERE email='' OR 1=1--' AND password=...
    DB-->>API: First user record (admin)
    API-->>U: 200 {authentication: {token: adminJWT}}
```
<!-- QA: sequence diagram '3.3 Input Validation' has no alt/else failure path — consider adding error scenarios (invalid input, authentication failure, permission denied, etc.) -->

### 3.4 File Upload Security

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as Express API
    participant FS as File System

    U->>API: POST /file-upload (multipart, ZIP file)
    API->>API: checkUploadSize (200KB multer limit)
    API->>API: checkFileType (extension check only - no MIME validation)
    API->>API: handleZipFileUpload
    Note over API: ZIP extracted using unzipper - path traversal possible
    API->>FS: Write entry.path to uploads/complaints/
    Note over FS: absolutePath check uses includes() not startsWith() - bypassable
    FS-->>API: File written
    API-->>U: 204 No Content

    U->>API: POST /file-upload (XML file with XXE payload)
    API->>API: handleXmlUpload
    API->>API: libxml.parseXml(data, {noent: true})
    Note over API: External entity resolution enabled - XXE/LFI possible
    API-->>U: 410 Gone (but file parsed; XXE resolves /etc/passwd)
```
<!-- QA: sequence diagram '3.4 File Upload Security' has no alt/else failure path — consider adding error scenarios (invalid input, authentication failure, permission denied, etc.) -->

### 3.5 Secret Management

```mermaid
sequenceDiagram
    participant DEV as Developer
    participant CODE as Source Code
    participant RT as Runtime Process
    participant FS as Filesystem

    Note over CODE: lib/insecurity.ts:23 - RSA private key hardcoded in source
    Note over CODE: lib/insecurity.ts:44 - HMAC key hardcoded ('pa4qacea4VK9t9nGv7yZtwmj')
    CODE->>RT: Private key loaded at module import
    RT->>RT: JWT signed with hardcoded key
    RT->>FS: JWT public key read from encryptionkeys/jwt.pub
    Note over FS: encryptionkeys/ served via /encryptionkeys route (unauthenticated)
    FS-->>RT: Public key
    RT-->>DEV: Any attacker who reads source or /encryptionkeys can forge JWTs
```
<!-- QA: sequence diagram '3.5 Secret Management' has no alt/else failure path — consider adding error scenarios (invalid input, authentication failure, permission denied, etc.) -->

### 3.6 Database Security

```mermaid
sequenceDiagram
    participant U as User
    participant R as Route Handler
    participant ORM as Sequelize ORM
    participant DB as SQLite

    U->>R: GET /api/Users/1 (authenticated)
    R->>ORM: UserModel.findByPk(1)
    ORM->>DB: SELECT * FROM Users WHERE id=1 (parameterized)
    DB-->>ORM: User record
    ORM-->>R: User object (password excluded by model)
    R-->>U: 200 {data: user}

    U->>R: GET /rest/products/search?q=test
    Note over R: Raw SQL used here - NOT parameterized
    R->>DB: "SELECT * FROM Products WHERE name LIKE '%test%'"
    Note over DB: String interpolation - SQL injection risk
    DB-->>R: Products
    R-->>U: 200 {data: products}

    Note over ORM: Mixed approach: ORM for model CRUD (safe)\nRaw queries for search and login (vulnerable)
```
<!-- QA: sequence diagram '3.6 Database Security' has no alt/else failure path — consider adding error scenarios (invalid input, authentication failure, permission denied, etc.) -->

### 3.7 Frontend Security (XSS Paths)

```mermaid
sequenceDiagram
    participant A as Attacker
    participant DB as Backend DB
    participant U as Victim Browser
    participant ANGULAR as Angular SPA

    A->>DB: POST /api/Users {email: '<iframe src=javascript:alert(xss)>'}
    Note over DB: User model email setter skips sanitization when challenge enabled
    DB-->>A: 201 Created

    U->>ANGULAR: Navigate to /administration
    ANGULAR->>DB: GET /api/Users (all users)
    DB-->>ANGULAR: User list including malicious email
    ANGULAR->>ANGULAR: sanitizer.bypassSecurityTrustHtml(user.email)
    Note over ANGULAR: administration.component.ts:60 bypasses Angular DomSanitizer
    ANGULAR-->>U: DOM updated - XSS payload executes
    Note over U: Token from localStorage exfiltrated to attacker server
```
<!-- QA: sequence diagram '3.7 Frontend Security (XSS Paths)' has no alt/else failure path — consider adding error scenarios (invalid input, authentication failure, permission denied, etc.) -->

---

## 4. Assets

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|---------------|
| User Credentials (email + MD5 password hash) | Restricted | Stored in SQLite `Users` table; MD5 is reversible | T-003, T-004, T-007 |
| RSA Private Key | Restricted | Hardcoded in `lib/insecurity.ts:23`; used to sign all JWTs | T-001, T-016 |
| HMAC Secret Key | Restricted | Hardcoded in `lib/insecurity.ts:44`; used for coupon and security-answer HMAC | T-016 |
| JWT Access Tokens | Confidential | 6h RS256 tokens; stored in `localStorage` on client | T-002, T-015 |
| Payment Card Data | Restricted | Credit card numbers stored in `Cards` table (Sequelize/SQLite) | T-007, T-008 |
| User PII (name, address, email, last login IP) | Confidential | Stored in `Users`, `Address` tables | T-007, T-008 |
| Product Reviews & Orders | Internal | Stored in in-memory MarsDB; lost on restart | T-013 |
| Access Logs | Internal | `logs/access.log.*` — contains IP addresses, URLs, user-agents | T-019 |
| FTP Directory Files | Internal | `ftp/` directory — various sensitive files (legal.md, acquisition docs) | T-019 |
| Encryption Keys Directory | Restricted | `encryptionkeys/jwt.pub`, `premium.key` — served unauthenticated | T-016, T-020 |
| Application Source Code | Internal | Served via `/snippets/:challenge`; challenge code visible | T-018 |
| SQLite Database File | Restricted | `data/juiceshop.sqlite` — all relational data | T-007 |
| User Profile Images / Uploads | Internal | `uploads/` directory; user-controlled content | T-010, T-011 |

---

## 5. Attack Surface

| Entry Point | Protocol/Method | Authentication | Notes | Linked Threats |
|------------|----------------|---------------|-------|---------------|
| `POST /rest/user/login` | HTTP JSON | None | **No rate limit**; raw SQL injection | T-004, T-005, T-006 |
| `GET /rest/products/search?q=` | HTTP GET | None (public) | Raw SQL string interpolation; UNION injection | T-003 |
| `POST /file-upload` | HTTP multipart | None | ZIP traversal, XXE, YAML bomb | T-010, T-011, T-012 |
| `GET /ftp/:file` | HTTP GET | None | **Unauthenticated** file download from ftp/ | T-019 |
| `GET /encryptionkeys/:file` | HTTP GET | None | **Unauthenticated** key file download | T-020 |
| `GET /support/logs` + `/:file` | HTTP GET | None | **Unauthenticated** log file access with dir listing | T-019 |
| `GET /metrics` | HTTP GET | None | Prometheus metrics; internal topology disclosure | T-018 |
| `GET /api-docs` | HTTP GET | None | Swagger UI; full API surface exposed | T-018 |
| `POST /b2b/v2/orders` | HTTP JSON | JWT (any role) | `safeEval()` of user-supplied `orderLinesData` → RCE | T-009 |
| `POST /profile/image/url` | HTTP form | Cookie token | SSRF via user-supplied URL fetched server-side | T-013 |
| `GET /rest/user/whoami` | HTTP GET | Optional | Updates auth store from cookie token | T-001 |
| `PUT /rest/products/:id/reviews` | HTTP PUT | None | NoSQL injection in product reviews | T-014 |
| `PATCH /rest/products/reviews` | HTTP PATCH | JWT | NoSQL injection update | T-014 |
| `GET /rest/user/change-password` | HTTP GET (!) | Token via header | Password change via GET; no CSRF protection | T-017 |
| `POST /profile` | HTTP form | Cookie | No CSRF token; CSRF challenge confirmed | T-017 |
| `GET /redirect?to=` | HTTP GET | None | Open redirect; allowlist uses `url.includes()` → bypassable | T-015 |
| `GET /api/Users` | HTTP GET | JWT (any role) | Any authenticated user can list all users | T-008 |
| `POST /rest/chatbot/respond` | HTTP JSON | JWT | Chatbot can be crashed/manipulated | T-022 |
| `GET /.well-known/` | HTTP GET | None | Directory listing of .well-known files | T-018 |
| `WebSocket` | WS | None initially | Socket.io events for challenge notifications | T-022 |

---

## 6. Trust Boundaries

The application has three principal trust zones with several critical weaknesses in how they are enforced.

**Overall trust model:** Fail-open. The application applies authentication middleware selectively to specific route prefixes, leaving some routes deliberately unprotected. There is no edge-level enforcement, no network policy, and no mTLS between components (all co-located in a single process).

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|-------------|---------------|
| 1 | Internet → Application | Public internet | Express HTTP server (port 3000) | None — direct TCP access | No WAF, no rate limiting at edge, no TLS termination in default config | T-005, T-006 |
| 2 | Unauthenticated → Authenticated | Public routes | Protected REST/API routes | `security.isAuthorized()` = `express-jwt` middleware | Not applied uniformly; `GET /api/Users`, `/rest/products/search`, `/rest/track-order/:id` accessible without auth or with minimal auth | T-008 |
| 3 | Customer → Admin | Customer JWT | Admin routes + admin UI | Backend: `security.isAccounting()` per route; Frontend: `AdminGuard` / `AccountingGuard` | Frontend guards client-side only; role in JWT payload (attackers with forged JWTs can elevate) | T-002, T-008 |
| 4 | Application → Data Tier | Express process | SQLite file + MarsDB | Sequelize ORM (sometimes), raw `sequelize.query()` | Same process; no network boundary; raw SQL in login and search | T-003, T-004 |
| 5 | Application → File System | Express process | ftp/, logs/, encryptionkeys/ | None — `serveIndex` + `express.static` mounted without auth | Sensitive directories browsable and downloadable without any authentication | T-019, T-020 |
| 6 | Application → External OAuth | Express process | Google OAuth (implicit flow) | HTTPS | Deprecated implicit flow; `access_token` in URL fragment; no PKCE; password derived from email | T-015 |

---

## 7. Identified Security Controls

**Critical gaps summary:** The most severe control failures are: (1) no rate limiting on the login endpoint enabling brute-force and credential stuffing; (2) CORS configured with wildcard allowing any origin to make credentialed requests; (3) Content Security Policy is absent, maximizing XSS impact; (4) RSA private key hardcoded in source enabling universal JWT forgery; (5) MD5 used for password hashing (completely broken for credential storage).

**Legend:** ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness |
|--------|---------|---------------|--------------|
| **Identity & Access Management** | JWT-based authentication | [`lib/insecurity.ts:54`](vscode://file/root/juice-shop/lib/insecurity.ts:54) — `expressJwt` with RS256 public key | ⚠️ Partial — token not revocable; very old library version (0.1.3) |
| **Identity & Access Management** | Password hashing | [`lib/insecurity.ts:43`](vscode://file/root/juice-shop/lib/insecurity.ts:43) — `crypto.createHash('md5')` | ❌ Missing — MD5 is not a password hash; no salt; trivially reversible |
| **Identity & Access Management** | TOTP two-factor auth | [`routes/2fa.ts`](vscode://file/root/juice-shop/routes/2fa.ts) — `otplib` TOTP implementation | ⚠️ Partial — optional, not enforced; rate limit is 100/5min (too high) |
| **Identity & Access Management** | Login rate limiting | None on `POST /rest/user/login` | ❌ Missing — login endpoint has no rate limit |
| **Identity & Access Management** | Account lockout | None | ❌ Missing — no failed-attempt tracking |
| **Authorization** | Role-based access control | [`lib/insecurity.ts:144`](vscode://file/root/juice-shop/lib/insecurity.ts:144) — roles embedded in JWT, `isAccounting()`, `isAuthorized()` middleware | ⚠️ Partial — not uniformly applied; `GET /api/Users` allows any authenticated user to list all users |
| **Authorization** | Admin route protection | [`server.ts:362`](vscode://file/root/juice-shop/server.ts:362) — `security.isAuthorized()` on most admin-adjacent routes | 🔶 Weak — frontend `AdminGuard` is client-side only; backend lacks admin check on `GET /api/Users` |
| **Data Protection** | Encryption at rest | None — SQLite file stored as plain file | ❌ Missing — database not encrypted at rest |
| **Data Protection** | TLS in transit | Not configured in default Docker; application serves HTTP | ❌ Missing — no TLS termination at application layer |
| **Data Protection** | PII masking in logs | None | ❌ Missing — morgan `combined` format logs full URLs including potential sensitive params |
| **Secret Management** | Private key management | [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23) — RSA private key hardcoded in source | ❌ Missing — key hardcoded; anyone with source access can forge JWTs |
| **Secret Management** | HMAC key management | [`lib/insecurity.ts:44`](vscode://file/root/juice-shop/lib/insecurity.ts:44) — `'pa4qacea4VK9t9nGv7yZtwmj'` hardcoded | ❌ Missing — HMAC secret hardcoded |
| **Frontend Security** | Content Security Policy | Not present — `helmet.contentSecurityPolicy()` not called | ❌ Missing — no CSP header |
| **Frontend Security** | XSS filter | [`server.ts:187`](vscode://file/root/juice-shop/server.ts:187) — `helmet.xssFilter()` commented out | ❌ Missing — explicitly disabled |
| **Frontend Security** | Output encoding | [`frontend/src/app/search-result/search-result.component.ts:170`](vscode://file/root/juice-shop/frontend/src/app/search-result/search-result.component.ts:170) — `bypassSecurityTrustHtml` called | ❌ Missing — Angular DomSanitizer bypassed in multiple components |
| **Frontend Security** | JWT token storage | [`frontend/src/app/app.guard.ts:20`](vscode://file/root/juice-shop/frontend/src/app/app.guard.ts:20) — `localStorage.getItem('token')` | ❌ Missing — tokens in localStorage, XSS-accessible |
| **Output Encoding** | Parameterized queries (login) | [`routes/login.ts:34`](vscode://file/root/juice-shop/routes/login.ts:34) — raw string interpolation | ❌ Missing — SQL injection confirmed |
| **Output Encoding** | Parameterized queries (search) | [`routes/search.ts:23`](vscode://file/root/juice-shop/routes/search.ts:23) — raw string interpolation | ❌ Missing — SQL injection confirmed |
| **Output Encoding** | ORM usage for CRUD | Model-level operations use Sequelize ORM with parameterized queries | ✅ Adequate — standard CRUD via ORM is safe |
| **Audit & Logging** | Access logging | [`server.ts:338`](vscode://file/root/juice-shop/server.ts:338) — morgan `combined` to rotating file | ⚠️ Partial — covers HTTP access; no security event logging (auth failures, admin actions) |
| **Audit & Logging** | Winston logger | [`lib/logger.ts`](vscode://file/root/juice-shop/lib/logger.ts) — console transport only | 🔶 Weak — no structured log format; no SIEM integration |
| **Infrastructure & Network** | CORS policy | [`server.ts:181`](vscode://file/root/juice-shop/server.ts:181) — `cors()` with no options (wildcard) | ❌ Missing — allows all origins; comment says "Bludgeon solution" |
| **Infrastructure & Network** | Security headers (partial) | [`server.ts:185`](vscode://file/root/juice-shop/server.ts:185) — `helmet.noSniff()`, `helmet.frameguard()` | ⚠️ Partial — minimal helmet usage; no HSTS, no CSP, no referrer policy |
| **Infrastructure & Network** | Container user | [`Dockerfile:40`](vscode://file/root/juice-shop/Dockerfile:40) — `USER 65532` (non-root) | ✅ Adequate — runs as non-root in distroless image |
| **Infrastructure & Network** | Prometheus metrics auth | [`server.ts:718`](vscode://file/root/juice-shop/server.ts:718) — `GET /metrics` no auth | ❌ Missing — metrics exposed to internet with no authentication |
| **Dependency & Supply Chain** | Lock file | `package-lock.json` present | ✅ Adequate — lock file committed |
| **Dependency & Supply Chain** | Outdated libraries | `express-jwt@0.1.3`, `jsonwebtoken@0.4.0`, `sanitize-html@1.4.2` | ❌ Missing — critically outdated security-relevant libraries |
| **Security Testing & Pipeline** | SAST / secret scanning | No SAST tool configured in visible CI | ❌ Missing — no automated security testing in pipeline |
| **OAuth / OIDC** | PKCE for OAuth | Not present — implicit flow used | ❌ Missing — implicit flow deprecated per RFC 9700 |
| **OAuth / OIDC** | state parameter validation | [`frontend/src/app/oauth/oauth.component.ts`](vscode://file/root/juice-shop/frontend/src/app/oauth/oauth.component.ts) — no state param | ❌ Missing — CSRF on OAuth callback |
| **OAuth / OIDC** | Token not in URL | Implicit flow places `access_token` in URL fragment | ❌ Missing — token in URL leaks to Referer, logs |
| **SPA Architecture** | Token in localStorage | All components use `localStorage.getItem('token')` | ❌ Missing — XSS-accessible token storage |
| **SPA Architecture** | HttpOnly session cookie | Not used — token in localStorage only | ❌ Missing — no HttpOnly cookie protection |
| **SPA Architecture** | CSRF protection | No CSRF token; challenge explicitly shows CSRF is possible | ❌ Missing — profile update CSRF confirmed |

---

## 8. Threat Register

**Risk Distribution:** Critical: 5 · High: 8 · Medium: 7 · Low: 3 · **Total: 23**
**STRIDE Coverage:** Spoofing: 4 · Tampering: 7 · Repudiation: 2 · Information Disclosure: 6 · Denial of Service: 2 · Elevation of Privilege: 2

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|-----------|--------|------|------------------|-------------|
| <a id="t-001"></a>T-001 | Auth Module | Spoofing | Attacker uses the hardcoded RSA private key (committed to source in `lib/insecurity.ts:23`) to forge arbitrary JWT tokens with any user ID and role, bypassing all authentication controls without a valid password. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT RS256 verification using public key; tokens expire after 6h | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | Auth Module | Spoofing | Attacker steals a victim's JWT from `localStorage` via XSS and impersonates them for the 6h token lifetime. No server-side session revocation mechanism exists; logout only removes the token from the client. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | 6h token expiry | [M-002](#m-002), [M-006](#m-006) |
| <a id="t-003"></a>T-003 | REST API | Tampering | SQL injection in product search: `GET /rest/products/search?q=` passes user input directly into a raw SQL `LIKE` clause (`routes/search.ts:23`). Attacker can perform UNION-based injection to extract all user email addresses and MD5 password hashes from the Users table. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — unauthenticated endpoint, no parameterization | [M-003](#m-003) |
| <a id="t-004"></a>T-004 | Auth Module | Spoofing | SQL injection in login: `POST /rest/user/login` uses raw string interpolation for email and password in `routes/login.ts:34`. Classic `' OR 1=1--` payload authenticates as the first user (admin). | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-003](#m-003) |
| <a id="t-005"></a>T-005 | REST API | Denial of Service | No rate limiting on `POST /rest/user/login`. An attacker can perform unlimited brute-force or credential-stuffing attacks. 100 req/5min limit exists on reset-password and 2FA, but login itself is unlimited. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Rate limit on reset-password and 2FA but not login | [M-004](#m-004) |
| <a id="t-006"></a>T-006 | REST API | Denial of Service | File upload endpoint (`POST /file-upload`) accepts YAML files and processes them via `js-yaml.load()` inside a VM sandbox. A YAML bomb (billion laughs equivalent) can cause DoS by exhausting memory/CPU (`routes/fileUpload.ts:117`). | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | VM timeout of 2 seconds; multer 200KB size limit | [M-005](#m-005) |
| <a id="t-007"></a>T-007 | Data Tier | Information Disclosure | All user passwords stored as unsalted MD5 hashes (`models/user.ts:77`). MD5 is not a password hashing algorithm; rainbow tables and GPU cracking trivially reverse all passwords once the database is accessed (e.g., via SQL injection in T-003). | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | MD5 hash applied (no salting) | [M-007](#m-007) |
| <a id="t-008"></a>T-008 | REST API | Information Disclosure | Any authenticated user (any role) can enumerate all user accounts via `GET /api/Users` (`server.ts:362`). Response includes email, last login IP, profile image, role, and other PII. IDOR on basket endpoint allows cross-user basket access. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT authentication required; password/totpSecret excluded from model | [M-008](#m-008) |
| <a id="t-009"></a>T-009 | REST API | Tampering | Remote Code Execution via B2B order endpoint: `POST /b2b/v2/orders` passes user-supplied `orderLinesData` to `safeEval()` in a Node.js VM sandbox (`routes/b2bOrder.ts:23`). The `notevil` sandbox is known to be bypassable; arbitrary JS can escape the sandbox and execute on the host. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT auth required on B2B endpoint; `notevil` sandboxing attempted; VM timeout 2s | [M-009](#m-009) |
| <a id="t-010"></a>T-010 | File Handler | Tampering | Zip-slip path traversal: ZIP uploads to `POST /file-upload` are extracted with `unzipper` without adequate path validation (`routes/fileUpload.ts:44`). The check `absolutePath.includes(path.resolve('.'))` can be bypassed with specially crafted paths, allowing files to be written outside `uploads/complaints/`. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | `includes()` path check (insufficient) | [M-010](#m-010) |
| <a id="t-011"></a>T-011 | File Handler | Tampering | XXE (XML External Entity injection): The file upload handler processes XML using `libxmljs2` with `noent: true` (`routes/fileUpload.ts:83`), which resolves external entities. An attacker can use a crafted XML file to read arbitrary files from the server filesystem (e.g., `/etc/passwd`). | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | VM sandbox; 2s timeout | [M-011](#m-011) |
| <a id="t-012"></a>T-012 | REST API | Tampering | Server-Side Template Injection (SSTI) via Pug template engine: The user profile page (`/profile`) compiles Pug templates with user-controlled data (`routes/userProfile.ts`). If username is interpolated unsafely into the template string, an attacker can inject Pug directives to execute server-side code. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None confirmed | [M-012](#m-012) |
| <a id="t-013"></a>T-013 | REST API | Information Disclosure | Server-Side Request Forgery (SSRF): `POST /profile/image/url` fetches a user-supplied URL server-side (`routes/profileImageUrlUpload.ts:24`). Attacker can use `http://169.254.169.254/latest/meta-data/` to probe cloud metadata endpoints, or internal services. No URL scheme allowlist validated. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-013](#m-013) |
| <a id="t-014"></a>T-014 | REST API | Tampering | NoSQL injection in product reviews: `PUT /rest/products/:id/reviews` and `PATCH /rest/products/reviews` pass user-supplied data to MarsDB queries without sanitization. An attacker can craft operators (`$where`, `$gt`) to manipulate query logic. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT auth on PATCH; no sanitization | [M-014](#m-014) |
| <a id="t-015"></a>T-015 | Auth Module | Spoofing | OAuth implicit flow token in URL: The Google OAuth integration uses the deprecated implicit flow, placing the `access_token` in the URL fragment (`oauth.component.ts:28`). Tokens leak into browser history, server logs, and Referer headers. Additionally, no PKCE or `state` parameter validation is present. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | HTTPS in transit | [M-015](#m-015) |
| <a id="t-016"></a>T-016 | Auth Module | Information Disclosure | Unauthenticated access to encryption key files: `GET /encryptionkeys/jwt.pub` and `GET /encryptionkeys/premium.key` are served by `routes/keyServer.ts` with directory listing enabled (`server.ts:277`). The JWT public key allows attackers to confirm key material for the RS256 algorithm. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-016](#m-016) |
| <a id="t-017"></a>T-017 | REST API | Tampering | Cross-Site Request Forgery (CSRF): The `POST /profile` endpoint updates username with no CSRF token (`routes/updateUserProfile.ts:36`). The `changePassword` endpoint is `GET /rest/user/change-password` (password change via GET — also CSRF vulnerable). The application confirms these as intentional challenges. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Cookie-based token required (partial protection via SameSite if set) | [M-017](#m-017) |
| <a id="t-018"></a>T-018 | REST API | Information Disclosure | Multiple unauthenticated information disclosure endpoints: `/metrics` (Prometheus — exposes user counts, wallet balances, challenge stats), `/api-docs` (full Swagger API spec), `/.well-known/` (directory listing). These provide detailed intelligence for targeted attacks. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-018](#m-018) |
| <a id="t-019"></a>T-019 | Static File Server | Information Disclosure | Unauthenticated FTP directory listing and log access: `GET /ftp` serves directory listing of `ftp/` (containing legal documents, acquisition files). `GET /support/logs` serves access log files without authentication. Access logs may contain sensitive data from other users' sessions. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-016](#m-016) |
| <a id="t-020"></a>T-020 | Static File Server | Information Disclosure | Sensitive files in publicly accessible `encryptionkeys/` directory exposed via unauthenticated `GET /encryptionkeys/:file` with directory browsing. The `premium.key` file contains the unlock code for premium content. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-016](#m-016) |
| <a id="t-021"></a>T-021 | REST API | Repudiation | Insufficient security event logging: The application logs HTTP access via morgan but does not log authentication failures, admin actions, or privilege escalation events as structured security events. Attackers can perform exploitation activities without generating auditable records. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | morgan HTTP access logs | [M-019](#m-019) |
| <a id="t-022"></a>T-022 | REST API | Repudiation | Open redirect: `GET /redirect?to=` uses `url.includes(allowedUrl)` for allowlist checking (`lib/insecurity.ts:138`). An attacker can bypass this by using a URL that contains an allowed string as a substring (e.g., `https://evil.com/?x=https://github.com/juice-shop/juice-shop`) to redirect victims to malicious sites. | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Allowlist present (weak implementation) | [M-020](#m-020) |
| <a id="t-023"></a>T-023 | REST API | Elevation of Privilege | Insecure Direct Object Reference (IDOR) on basket: `GET /rest/basket/:id` and `POST /rest/basket/:id/checkout` require authentication but do not verify that the basket ID belongs to the requesting user. An authenticated user can access or check out another user's basket by guessing the integer basket ID. | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT authentication | [M-021](#m-021) |

---

## 9. Critical Findings

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-001 — Hardcoded RSA Private Key Enables Universal JWT Forgery

**Scenario:** The complete RSA-2048 private key used to sign all JWT tokens is hardcoded as a string literal in [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23). Any party with access to the source code (public GitHub repository) can use this key to generate valid JWT tokens with arbitrary user IDs, roles (including `admin`), and claims.

**Current state:** Private key embedded in source. Public key at `encryptionkeys/jwt.pub` served unauthenticated. Token expiry is 6h and no revocation mechanism exists. Library `jsonwebtoken@0.4.0` is severely outdated.

→ **Mitigation:** [M-001 — Externalize and rotate the RSA JWT signing key](#m-001)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-002 — XSS-Accessible JWT in localStorage with No Revocation

**Scenario:** JWT tokens are stored in `localStorage` by the Angular SPA ([`app.guard.ts:20`](vscode://file/root/juice-shop/frontend/src/app/app.guard.ts:20)). Any XSS vulnerability (multiple confirmed in this codebase) allows an attacker to steal the token and impersonate the victim for the full 6h expiry. Server-side logout does not invalidate the token.

**Current state:** Token in localStorage. No HttpOnly cookie. No server-side token revocation. No CSP to limit XSS impact.

→ **Mitigation:** [M-002 — Move JWT to HttpOnly cookie and implement server-side revocation](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-003 — SQL Injection in Product Search (Unauthenticated)

**Scenario:** `GET /rest/products/search?q=` concatenates user input directly into a raw SQL query at [`routes/search.ts:23`](vscode://file/root/juice-shop/routes/search.ts:23). No authentication is required. An attacker can perform UNION-based SQL injection to extract the entire Users table including email addresses and MD5 password hashes.

**Current state:** Raw `sequelize.query()` with string interpolation. No parameterization. Unauthenticated endpoint. Confirmed vulnerable (labeled `unionSqlInjectionChallenge`).

→ **Mitigation:** [M-003 — Replace raw SQL with parameterized queries](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-004 — SQL Injection in Login Authentication

**Scenario:** `POST /rest/user/login` interpolates `email` and `password` directly into a SQL query at [`routes/login.ts:34`](vscode://file/root/juice-shop/routes/login.ts:34). Classic `' OR 1=1--` payload bypasses authentication and logs the attacker in as the first user in the database (typically the admin account).

**Current state:** Raw SQL with string interpolation. No rate limiting on this endpoint. Confirmed vulnerable (labeled `loginAdminChallenge`).

→ **Mitigation:** [M-003 — Replace raw SQL with parameterized queries](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-005 — No Rate Limiting on Login Endpoint

**Scenario:** `POST /rest/user/login` has no rate limiting ([`server.ts:594`](vscode://file/root/juice-shop/server.ts:594)). An attacker can perform unlimited authentication attempts per second. Combined with the MD5 password hashing ([T-007](#t-007)) and SQL injection ([T-004](#t-004)), this means credential-stuffing attacks from any data breach can be automated without throttling.

**Current state:** Rate limit exists on `/rest/user/reset-password` (100/5min) and 2FA (100/5min), but not on the primary login endpoint.

→ **Mitigation:** [M-004 — Apply rate limiting to POST /rest/user/login](#m-004)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-007 — MD5 Used for Password Hashing (No Salt)

**Scenario:** All user passwords are stored as unsalted MD5 hashes ([`models/user.ts:77`](vscode://file/root/juice-shop/models/user.ts:77) via `lib/insecurity.ts:43`). MD5 is not a password hashing algorithm. A GPU array can crack billions of MD5 hashes per second. Rainbow tables exist for common passwords. Once the database is obtained via SQL injection ([T-003](#t-003)), all passwords are immediately recoverable.

**Current state:** `security.hash(clearTextPassword)` → `crypto.createHash('md5').update(data).digest('hex')`.

→ **Mitigation:** [M-007 — Replace MD5 with bcrypt or Argon2 for password storage](#m-007)

---

## 10. Mitigation Register

### <a id="m-001"></a>M-001 · Externalize and Rotate the RSA JWT Signing Key

**Addresses:** [T-001](#t-001)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** The hardcoded private key means any person with source code access (the public GitHub repo) can forge admin tokens immediately. Rotation is impossible without a code deployment.

**How:**
1. Generate a new RSA-2048 key pair outside the application source tree
2. Load the private key from environment variable or a secrets manager (AWS Secrets Manager, HashiCorp Vault) at startup
3. Remove the hardcoded key from `lib/insecurity.ts:23`
4. Rotate all existing tokens by changing the key (existing tokens will be invalidated)
5. Add a key rotation mechanism (at minimum support environment-variable-based key reload)

```typescript
// Before (lib/insecurity.ts:23):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAI...'

// After:
const privateKey = process.env.JWT_PRIVATE_KEY
  ?? (() => { throw new Error('JWT_PRIVATE_KEY environment variable is required') })()
```

**Reference:** [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html), CWE-321

---

### <a id="m-002"></a>M-002 · Move JWT to HttpOnly Cookie and Implement Server-Side Revocation

**Addresses:** [T-002](#t-002)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** Tokens in localStorage are readable by any JavaScript on the page. XSS vulnerabilities (multiple confirmed) immediately enable complete session theft. HttpOnly cookies are inaccessible to JavaScript.

**How:**
1. On successful login, set JWT as an HttpOnly, Secure, SameSite=Strict cookie instead of returning it in the JSON body
2. Remove `localStorage.setItem('token', ...)` from all Angular components
3. Implement a server-side token denylist (Redis or in-memory set) keyed on JWT `jti` claim
4. On logout, add the token's `jti` to the denylist; check denylist in `isAuthorized()` middleware
5. Update `express-jwt` to current version (^8.x) and set proper options

```typescript
// After login - set HttpOnly cookie instead of JSON body token:
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 6 * 60 * 60 * 1000 // 6h
})
```

**Reference:** [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), CWE-614

---

### <a id="m-003"></a>M-003 · Replace Raw SQL with Parameterized Queries

**Addresses:** [T-003](#t-003), [T-004](#t-004)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** Raw SQL with string interpolation allows an attacker to manipulate the query structure, extracting the entire database or bypassing authentication.

**How:**
1. Replace the raw query in `routes/login.ts:34` with Sequelize ORM's `findOne()`:
2. Replace the raw query in `routes/search.ts:23` with parameterized `LIKE` binding:

```typescript
// Before (routes/login.ts:34):
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`)

// After:
UserModel.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password),
    deletedAt: null
  }
})

// Before (routes/search.ts:23):
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL)`)

// After:
ProductModel.findAll({
  where: {
    [Op.and]: [
      { deletedAt: null },
      { [Op.or]: [
        { name: { [Op.like]: `%${criteria}%` } },
        { description: { [Op.like]: `%${criteria}%` } }
      ]}
    ]
  }
})
```

**Reference:** [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), CWE-89

---

### <a id="m-004"></a>M-004 · Apply Rate Limiting to POST /rest/user/login

**Addresses:** [T-005](#t-005)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** Unlimited login attempts enable brute-force and credential stuffing. Combined with MD5 hashing, an attacker who obtains hashes can also verify them online.

**How:**
1. Add `express-rate-limit` before the login route handler, mirroring the existing pattern on `/rest/user/reset-password`
2. Use a stricter limit (e.g., 10 attempts per 15 minutes per IP)
3. Consider progressive delays or CAPTCHA after failed attempts

```typescript
// In server.ts, before: app.post('/rest/user/login', login())
app.post('/rest/user/login',
  rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 10,
    message: 'Too many login attempts, please try again later.',
    keyGenerator: (req) => req.headers['x-forwarded-for']?.toString() ?? req.ip
  }),
  login()
)
```

**Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), CWE-307

---

### <a id="m-005"></a>M-005 · Restrict File Upload Types and Disable YAML/XML Processing

**Addresses:** [T-006](#t-006)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Processing YAML and XML from untrusted uploads with insufficient sandboxing allows DoS (YAML bomb) and LFI (XXE). The deprecated file types (YAML, XML) should be rejected at the validation layer.

**How:**
1. Update `checkFileType()` in `routes/fileUpload.ts` to reject YAML and XML uploads entirely, or at minimum disable `noent: true` in `libxml.parseXml()` to prevent XXE
2. For YAML: Use `yaml.load()` with `schema: yaml.FAILSAFE_SCHEMA` or disable YAML upload
3. Implement MIME type validation using the `file-type` library (already a dependency) in addition to extension checking

```typescript
// For XML: disable external entity resolution
const xmlDoc = libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })

// For YAML: restrict to FAILSAFE_SCHEMA to prevent billion laughs
const yamlData = yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })
```

**Reference:** [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), CWE-611

---

### <a id="m-006"></a>M-006 · Add Content Security Policy to Prevent XSS Impact

**Addresses:** [T-002](#t-002)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** Without a CSP, any XSS vulnerability (multiple confirmed) allows arbitrary script execution, which can exfiltrate localStorage tokens, perform actions as the victim, or call external attackers' servers.

**How:**
1. Enable `helmet.contentSecurityPolicy()` with a restrictive policy
2. Move from `localStorage` to HttpOnly cookie for tokens first ([M-002](#m-002)), then tighten CSP
3. Use nonce-based CSP for inline scripts if needed

```typescript
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],  // Narrow this further
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"]
  }
}))
```

**Reference:** [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), CWE-1021

---

### <a id="m-007"></a>M-007 · Replace MD5 with bcrypt or Argon2 for Password Storage

**Addresses:** [T-007](#t-007)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** MD5 is a general-purpose hash, not a password hash. It has no work factor, no salting in this implementation, and is trivially crackable with rainbow tables or GPU acceleration (billions of hashes/second).

**How:**
1. Install `bcrypt` or `argon2` npm package
2. Replace `security.hash()` in `models/user.ts:77` with bcrypt/Argon2 hashing
3. Implement a migration to rehash existing passwords on next login
4. Update the login query to use `bcrypt.compare()` instead of hash comparison

```typescript
import bcrypt from 'bcrypt'
const SALT_ROUNDS = 12

// In user model password setter:
set (clearTextPassword: string) {
  this.setDataValue('password', bcrypt.hashSync(clearTextPassword, SALT_ROUNDS))
}

// In login route:
const passwordMatch = await bcrypt.compare(req.body.password, authenticatedUser.password)
```

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), CWE-916

---

### <a id="m-008"></a>M-008 · Restrict GET /api/Users to Admin Role

**Addresses:** [T-008](#t-008)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Any authenticated user can enumerate all registered users' emails, last login IPs, profile images, and roles. This enables targeted phishing and credential stuffing.

**How:**
1. Replace `security.isAuthorized()` with a custom middleware that also checks for admin role on `GET /api/Users`
2. Add IDOR check on basket endpoints to ensure `req.user.bid` matches the requested basket ID

```typescript
// server.ts - before GET /api/Users route
app.get('/api/Users', security.isAuthorized(), (req, res, next) => {
  const token = security.authenticatedUsers.from(req)
  if (token?.data?.role !== security.roles.admin) {
    return res.status(403).json({ error: 'Admin role required' })
  }
  next()
})
```

**Reference:** [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html), CWE-639

---

### <a id="m-009"></a>M-009 · Remove safeEval() from B2B Order Endpoint

**Addresses:** [T-009](#t-009)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** `notevil` and Node.js `vm.runInContext()` are not isolation boundaries — both are known to be bypassable. User-supplied code should never be evaluated on the server.

**How:**
1. Remove `safeEval` and `vm.runInContext` from `routes/b2bOrder.ts`
2. Parse the `orderLinesData` field as a structured JSON object instead of evaluating it as code
3. Validate the JSON structure against an explicit schema

```typescript
// Before:
const sandbox = { safeEval, orderLinesData }
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// After:
const orderLines = JSON.parse(orderLinesData)  // Parse, don't eval
// Validate against expected schema (array of {product, quantity, price})
if (!Array.isArray(orderLines)) throw new Error('Invalid order format')
```

**Reference:** CWE-94, [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)

---

### <a id="m-010"></a>M-010 · Fix ZIP Path Traversal Check

**Addresses:** [T-010](#t-010)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** `absolutePath.includes(path.resolve('.'))` can be bypassed via path manipulation. The safe check is to verify the resolved path starts with the allowed directory.

**How:**
1. Replace `includes()` with `startsWith()` in `routes/fileUpload.ts:44`
2. Normalize the path before comparison to remove `../` sequences

```typescript
// Before (routes/fileUpload.ts:44):
if (absolutePath.includes(path.resolve('.'))) {

// After:
const safeBase = path.resolve('uploads/complaints') + path.sep
if (absolutePath.startsWith(safeBase)) {
```

**Reference:** CWE-22, [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

### <a id="m-011"></a>M-011 · Disable External Entity Resolution in XML Parser

**Addresses:** [T-011](#t-011)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** `noent: true` instructs libxmljs2 to resolve external entities, enabling attackers to read files from the server filesystem via XXE.

**How:**
1. Change `noent: true` to `noent: false` in `routes/fileUpload.ts:83`
2. Consider rejecting XML uploads entirely if the feature is deprecated anyway (the error message already says "deprecated for security reasons")

```typescript
// Before (routes/fileUpload.ts:83):
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })

// After:
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })', sandbox, { timeout: 2000 })
```

**Reference:** [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), CWE-611

---

### <a id="m-012"></a>M-012 · Sanitize User Input Before Template Rendering (SSTI)

**Addresses:** [T-012](#t-012)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** If user-controlled data (username, profile fields) is embedded into a Pug template string before compilation, an attacker can inject template directives that execute server-side code.

**How:**
1. Review `routes/userProfile.ts` template compilation — use Pug's `locals` variable binding instead of string interpolation
2. Sanitize all user-controlled strings used in template context
3. Prefer `pug.renderFile()` with a static template file and a locals object rather than dynamic template string construction

```typescript
// Prefer:
const html = pug.renderFile('views/userProfile.pug', {
  username: sanitizeHtml(user.username),  // sanitized local variable
  ...otherSafeLocals
})
```

**Reference:** CWE-94, [Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)

---

### <a id="m-013"></a>M-013 · Implement SSRF Allowlist for Profile Image URL Fetch

**Addresses:** [T-013](#t-013)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** The server-side `fetch(url)` call in `routes/profileImageUrlUpload.ts:24` follows any URL including `file://`, `gopher://`, or internal metadata services.

**How:**
1. Validate the URL scheme (allow only `https:`)
2. Resolve the URL's hostname and check it against a blocklist (block RFC-1918 ranges, loopback, link-local)
3. Use a dedicated HTTP client library that supports egress filtering

```typescript
function isSafeImageUrl (url: string): boolean {
  try {
    const parsed = new URL(url)
    if (parsed.protocol !== 'https:') return false
    // Add DNS resolution check against blocklist
    return true
  } catch { return false }
}

if (!isSafeImageUrl(url)) {
  return res.status(400).json({ error: 'Invalid image URL' })
}
```

**Reference:** [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), CWE-918

---

### <a id="m-014"></a>M-014 · Sanitize NoSQL Query Inputs for Product Reviews

**Addresses:** [T-014](#t-014)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** MarsDB operator injection allows attackers to manipulate queries by passing MongoDB-style operators as field values.

**How:**
1. Validate and reject any input that contains MongoDB/MarsDB operator keys (`$where`, `$gt`, `$regex`, etc.) before passing to the collection
2. Use a JSON schema validator (e.g., `ajv`) to enforce the expected shape of review objects

```typescript
function sanitizeNoSqlInput (obj: any): boolean {
  if (typeof obj !== 'object' || obj === null) return true
  return !Object.keys(obj).some(key => key.startsWith('$'))
}
```

**Reference:** [OWASP NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection), CWE-943

---

### <a id="m-015"></a>M-015 · Migrate Google OAuth to Authorization Code Flow with PKCE

**Addresses:** [T-015](#t-015)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** High

**Why:** The implicit flow (receiving `access_token` directly in URL fragment) is deprecated per RFC 9700. Tokens in URLs leak to server logs, Referer headers, and browser history. PKCE prevents authorization code interception attacks.

**How:**
1. Switch to authorization code flow: receive an authorization code, exchange server-side for tokens
2. Implement PKCE (`code_verifier`, `code_challenge` with `S256`)
3. Validate the `state` parameter on callback to prevent CSRF
4. Store tokens in HttpOnly cookie, not `localStorage`

**Reference:** [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700), [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

---

### <a id="m-016"></a>M-016 · Restrict Access to Sensitive Directories (ftp, encryptionkeys, logs)

**Addresses:** [T-016](#t-016), [T-019](#t-019), [T-020](#t-020)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** The `ftp/`, `encryptionkeys/`, and `support/logs` directories are served with directory listing and no authentication, exposing encryption keys, access logs, and sensitive documents to any internet user.

**How:**
1. Add `security.isAuthorized()` middleware before the `/ftp`, `/encryptionkeys`, and `/support/logs` route registrations
2. Disable directory listing for these directories (`serveIndex` should not be used for sensitive paths)
3. Move encryption keys out of the web server root entirely; load from environment or secrets manager

```typescript
// Protect ftp directory:
app.use('/ftp', security.isAuthorized(), serveIndexMiddleware, serveIndex('ftp', { icons: true }))

// Better: remove encryptionkeys from web root entirely
// Load from process.env.JWT_PUBLIC_KEY instead
```

**Reference:** [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure), CWE-538

---

### <a id="m-017"></a>M-017 · Implement CSRF Protection and Move Password Change to POST

**Addresses:** [T-017](#t-017)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** `GET /rest/user/change-password` accepts password changes via a GET request, making it trivially CSRF-exploitable via any `<img src>` tag. The profile update endpoint has no CSRF token.

**How:**
1. Change `GET /rest/user/change-password` to `POST` and remove query parameters for sensitive data
2. Implement synchronizer token pattern (CSRF token in form/header) or move to HttpOnly cookie + `SameSite=Strict` (which provides CSRF protection)
3. Install `csurf` or equivalent CSRF middleware for all state-changing routes

**Reference:** [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), CWE-352

---

### <a id="m-018"></a>M-018 · Restrict or Authenticate Observability Endpoints

**Addresses:** [T-018](#t-018)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** `/metrics` exposes user counts, wallet balances, challenge statistics, and system information. `/api-docs` reveals the full API surface. These endpoints provide an attacker with detailed reconnaissance intelligence.

**How:**
1. Add authentication or IP-based restriction on `GET /metrics` (restrict to monitoring subnet/localhost)
2. Disable Swagger UI (`/api-docs`) in production builds, or add authentication
3. Use environment-based feature flags: `if (process.env.NODE_ENV === 'production') { /* disable swagger */ }`

```typescript
// Restrict metrics to localhost:
app.get('/metrics',
  (req, res, next) => {
    if (req.ip !== '127.0.0.1' && req.ip !== '::1') {
      return res.status(403).end()
    }
    next()
  },
  metrics.serveMetrics()
)
```

**Reference:** CWE-200, [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

### <a id="m-019"></a>M-019 · Implement Structured Security Event Logging

**Addresses:** [T-021](#t-021)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Security events (failed logins, privilege escalation attempts, admin actions) are not logged as structured events. Incident investigation is impossible without this data.

**How:**
1. Extend the winston logger to write structured JSON logs (not `winston.format.simple()`)
2. Log security events: failed login (with IP, email attempted), successful admin login, privilege denied events, file upload events, password changes
3. Add a `security` log category to distinguish from application logs

```typescript
// In lib/logger.ts:
export const securityLogger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.File({ filename: 'logs/security.log' })]
})

// In routes/login.ts on failure:
securityLogger.warn({ event: 'login_failed', email: req.body.email, ip: req.ip })
```

**Reference:** [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), CWE-778

---

### <a id="m-020"></a>M-020 · Fix Open Redirect Allowlist to Use Exact Matching

**Addresses:** [T-022](#t-022)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** `url.includes(allowedUrl)` allows bypass by embedding the allowed URL as a substring in a longer attacker-controlled URL (e.g., `https://evil.com/?x=https://github.com/juice-shop/juice-shop`).

**How:**
1. Use `url.startsWith(allowedUrl)` instead of `url.includes(allowedUrl)` in `lib/insecurity.ts:138`
2. Validate that the URL is an exact match or starts with one of the allowed base URLs
3. Consider removing the redirect endpoint entirely if not needed functionally

```typescript
// Before (lib/insecurity.ts:138):
allowed = allowed || url.includes(allowedUrl)

// After:
allowed = allowed || url === allowedUrl || url.startsWith(allowedUrl + '/')
```

**Reference:** [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), CWE-601

---

### <a id="m-021"></a>M-021 · Add User Ownership Check on Basket Endpoints (IDOR fix)

**Addresses:** [T-023](#t-023)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Any authenticated user can access any other user's basket by supplying a different integer basket ID, allowing them to view items or trigger checkout for other users.

**How:**
1. In `routes/basket.ts`, after retrieving the basket, verify `basket.UserId === req.user.id`
2. Return 403 if the basket does not belong to the requesting user

```typescript
// In routes/basket.ts retrieveBasket:
const basket = await BasketModel.findByPk(req.params.id)
if (!basket || basket.UserId !== loggedInUser.data.id) {
  return res.status(403).json({ error: 'Access denied' })
}
```

**Reference:** [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References), CWE-639

---

## 11. Out of Scope

The following areas were not analyzed in this assessment:

- **Third-party dependencies CVE scanning** — A full SCA (Software Composition Analysis) scan was not run (`WITH_SCA=false`). Known outdated dependencies noted include `express-jwt@0.1.3`, `jsonwebtoken@0.4.0`, `sanitize-html@1.4.2`, and `unzipper@0.9.15`, which should be assessed with `npm audit` or a dedicated SCA tool.
- **Monitoring infrastructure** — The Prometheus/Grafana monitoring stack in `monitoring/` was not analyzed in depth.
- **CTF/challenge engine internals** — The `lib/antiCheat.ts`, `lib/challengeUtils.ts`, and challenge verification code are out of scope as they are Juice Shop-specific mechanisms.
- **Web3/NFT/Ethereum integration** — The `routes/nftMint.ts`, `routes/web3Wallet.ts`, and `routes/checkKeys.ts` endpoints were identified but not deeply analyzed for blockchain-specific vulnerabilities (e.g., smart contract flaws, private key handling).
- **Vagrant deployment configuration** — The `vagrant/` directory was not analyzed.
- **Frontend Angular unit test security** — Test files were scanned for patterns but not analyzed for security relevance.
- **Intentionally accepted risks (design)** — All documented vulnerabilities are intentional Juice Shop training exercises. In a real application, all would be remediated. The intentional nature is acknowledged but does not reduce their severity classification in this model.
- **Supply chain / CI-CD pipeline** — No GitHub Actions or CI configuration files were found in scope; supply chain security of the build pipeline was not assessed.
