# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-09T18:35:00Z |
| Analysis Duration | 9 min 04 s |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Agent Models | all agents: claude-sonnet-4-6 |
| Input Tokens | unavailable |
| Output Tokens | unavailable |
| Cache Read Tokens | unavailable |
| Cache Write Tokens | unavailable |
| Estimated Cost | unavailable |
| Context Sources | None (external endpoint unavailable; no business-context.md found) |

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
- [8. Threat Register](#8-threat-register)
- [9. Critical Findings](#9-critical-findings)
- [10. Mitigation Register](#10-mitigation-register)
- [11. Out of Scope](#11-out-of-scope)

---

## Management Summary

This threat model identified **25 threats** across 5 components of OWASP Juice Shop v19.2.1, with the following risk distribution:

| Risk Level | Count | Key Areas |
|------------|-------|-----------|
| 🔴 Critical | 6 | SQL injection, RCE via VM sandbox, XXE, hardcoded private key, MD5 passwords, wildcard CORS |
| 🟠 High | 9 | Path traversal, IDOR, JWT algorithm confusion, directory listing, insecure redirect, XSS, chatbot injection |
| 🟡 Medium | 7 | No login rate limit, CSRF absent, cookie security, log exposure, password reset weakness, unsafe deserialization, supply chain |
| 🟢 Low | 3 | Missing HSTS, missing CSP, missing Referrer-Policy |

### Top Findings

- **[T-001 — SQL Injection: Login and Search Endpoints](#t-001):** Unauthenticated SQL injection in login (`routes/login.ts:34`) and search (`routes/search.ts:23`) allows full database extraction including all user credentials and admin takeover.
- **[T-002 — Hardcoded RSA Private Key for JWT Signing](#t-002):** The full 1024-bit RSA private key is committed in source code (`lib/insecurity.ts:23`), allowing any reader to forge arbitrary JWT tokens with any role including admin.
- **[T-003 — Remote Code Execution: B2B Order vm.runInContext](#t-003):** User-controlled input is evaluated in a Node.js VM sandbox (`routes/b2bOrder.ts:23`) that can be escaped for full server-side code execution.
- **[T-004 — XML External Entity (XXE) Injection](#t-004):** File upload with `noent: true` (`routes/fileUpload.ts:83`) enables XXE attacks — server-side file disclosure and potential SSRF.
- **[T-005 — MD5 Password Hashing](#t-005):** Passwords are stored as unsalted MD5 hashes (`lib/insecurity.ts:43`), trivially reversible with rainbow tables.
- **[T-006 — Wildcard CORS with No Restrictions](#t-006):** `app.use(cors())` with no options (`server.ts:182`) allows any origin to make credentialed cross-origin requests.

### Recommended Priority Actions

1. **[M-001 — Replace MD5 with bcrypt/Argon2 for Password Hashing](#m-001)** (Effort: Low) — Eliminate trivially reversible password storage; blocks mass credential compromise.
2. **[M-002 — Parameterize All SQL Queries](#m-002)** (Effort: Low) — Replace raw SQL string interpolation with Sequelize parameterized queries or prepared statements.
3. **[M-003 — Remove Hardcoded RSA Private Key from Source Code](#m-003)** (Effort: Low) — Load private key from environment variable or secrets manager; rotate immediately.
4. **[M-004 — Disable XXE and Sandbox B2B Execution](#m-004)** (Effort: Medium) — Disable external entity resolution in XML parser; replace vm.runInContext with safe schema validation.
5. **[M-005 — Restrict CORS to Explicit Origin Allowlist](#m-005)** (Effort: Low) — Replace wildcard CORS with specific allowed origins to prevent cross-site credential theft.

### Overall Security Rating

🔴 **Critical Gaps** — The application contains multiple unauthenticated remote code execution and SQL injection vectors, hardcoded cryptographic private keys committed to source control, and critically weak password hashing. These represent complete compromise of the application and its users.

→ *Full details in [Threat Register](#8-threat-register) and [Mitigation Register](#10-mitigation-register).*

---

## 1. System Overview

OWASP Juice Shop v19.2.1 is an intentionally vulnerable web application maintained by the OWASP Foundation as a security training and awareness platform. It is a fully functional e-commerce application (user registration, product browsing, shopping basket, payment, order history) that deliberately implements security vulnerabilities across all OWASP Top 10 categories and many beyond as interactive hacking challenges.

**Deployment context:** Single Docker container (port 3000), runs as non-root UID 65532 on a distroless Node.js 24 base. No TLS at application level (intended to run behind a reverse proxy or standalone for training). Publicly accessible at https://demo.owasp-juice.shop and configurable for CTF and corporate training scenarios.

**Users:** Security professionals, developers, students, and CTF participants. No real PII or financial data in training deployments. Production deployments (for institutional training) may have real user accounts.

**Complexity tier: Moderate** — single deployable Node.js/Express monolith with an Angular SPA frontend, SQLite + MongoDB databases, and WebSocket support. Multiple distinct security domains (auth, file handling, chatbot, REST API, frontend) warranting Container-level modeling.

**Repo URL:** https://github.com/juice-shop/juice-shop
**Team:** OWASP Juice Shop project (Bjoern Kimminich and contributors)
**Compliance scope:** Not formally specified. GDPR data erasure feature present.

**Context sources:** None available (external context endpoint unreachable; no business-context.md; no known-threats.yaml).

**Overall security impression:** This application is intentionally insecure and functions as a living catalog of web application vulnerabilities. Every critical vulnerability class is represented with working exploits. The threat model documents these as real risks because in real deployments (corporate training, institutional use) the same patterns would represent genuine business risk. The architecture itself has correct structural elements (non-root containers, dependency injection, role-based access structure) alongside the intentional vulnerabilities.

---

## 2. Architecture Diagrams

The following diagrams model the system architecture at different abstraction levels using the C4 model. Nodes highlighted with a red border (`:::risk`) indicate components or boundaries with at least one Medium-severity associated threat.

### 2.1 System Context

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["🌐 Public Internet · untrusted"]
        User["Anonymous User\nWeb browser"]:::person
        AuthUser["Authenticated User\nCustomer / Admin"]:::person
        Attacker["Attacker\nExternal threat actor"]:::person
    end

    subgraph APP["🔒 Application Tier"]
        JuiceShop["OWASP Juice Shop\nNode.js Express\nv19.2.1"]:::risk
    end

    subgraph EXTERNAL_SVC["🌐 External Services"]
        Google["Google OAuth2\nIdentity Provider"]:::external
        NPM["npm Registry\nPackage source"]:::external
    end

    User -->|"HTTP GET/POST · port 3000"| JuiceShop
    AuthUser -->|"HTTP REST + JWT · port 3000"| JuiceShop
    Attacker -->|"HTTP attack traffic · port 3000"| JuiceShop
    JuiceShop -->|"OAuth2 token exchange · HTTPS"| Google
    JuiceShop -.->|"npm install · HTTPS"| NPM

%% Trust Boundary Key:
%% INTERNET → APP: No TLS enforcement at app level; no WAF; direct TCP to port 3000
%% APP → External Services: HTTPS; Google OAuth redirect allowlist configured
```

### 2.2 Containers

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["🌐 Public Internet · untrusted"]
        Browser["User Browser\nAngular SPA consumer"]:::person
    end

    subgraph CONTAINER["🔒 Juice Shop Container · UID 65532"]
        SPA["Angular SPA\nTypeScript · Angular\nServed as static files"]:::risk
        API["Express REST API\nNode.js · Express 4.22.1\nAll REST + auto-CRUD routes"]:::risk
        Chatbot["Chatbot Service\njuicy-chat-bot · NLP\nPOST /rest/chatbot/*"]:::risk
        FileHandler["File Handler\nmulter · libxmljs2 · unzipper\nPOST /file-upload"]:::risk
        AuthModule["Auth Module\nexpress-jwt 0.1.3 · jsonwebtoken\nJWT RS256 signing"]:::risk
    end

    subgraph DATA["🔐 Data Tier · restricted"]
        SQLite["SQLite Database\nSequelize ORM\nUsers, Products, Orders"]:::db
        MongoDB["MongoDB\nmongoose\nProduct Reviews"]:::db
        FTP["FTP Directory\nStatic file serving\n/ftp/ publicly browsable"]:::risk
        Logs["Log Files\nWinston · Morgan\n/support/logs/ browsable"]:::risk
    end

    Browser -->|"HTTPS GET · static assets"| SPA
    Browser -->|"HTTP REST + JWT Bearer · port 3000"| API
    SPA -->|"XHR/fetch · HTTP REST"| API
    API -->|"Sequelize ORM · SQL"| SQLite
    API -->|"mongoose · TCP 27017"| MongoDB
    API --> AuthModule
    API --> Chatbot
    API --> FileHandler
    API -->|"read/write · local fs"| FTP
    API -->|"write · local fs"| Logs

%% Trust Boundary Key:
%% Browser → SPA: Static HTTPS served by Express; no TLS enforcement in app code
%% Browser → API: JWT Bearer token; no CSRF protection; CORS is wildcard
%% API → SQLite: Local file access; ORM parameterized for most queries; raw SQL in login/search
%% API → MongoDB: Local TCP; no auth credential shown in config
%% FTP and Logs: Publicly browsable via HTTP — no auth at directory level
```

### 2.3 Technology Architecture

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph CLIENT["Client Layer"]
        Angular["Angular SPA\nTypeScript · Material UI\nBuilt to frontend/dist/"]
    end

    subgraph SERVER["Server Layer · Node.js 24"]
        Express["Express 4.22.1\nHTTP Server · port 3000\ncookieParser, bodyParser, morgan"]:::risk
        Helmet["Helmet 4.6.0\nnoSniff + frameguard only\nCSP disabled by design"]:::risk
        JWT["express-jwt 0.1.3\njsonwebtoken · RS256\nHardcoded private key!"]:::risk
        CORS["CORS · Wildcard\ncors() no options\nAll origins allowed"]:::risk
        RateLimit["express-rate-limit 7.5.1\nOnly on /reset-password\nand 2FA endpoints"]
        Multer["Multer 1.4.5\nFile upload handler\nmemory + disk storage"]
        Finale["finale-rest\nAuto-generated CRUD API\n/api/* endpoints"]
    end

    subgraph PERSISTENCE["Persistence Layer"]
        Sequelize["Sequelize 6.37.3\nSQLite adapter\nORM + raw SQL mixed"]:::risk
        SQLiteDB["SQLite\nfile or in-memory\nUsers · Orders · Cards"]:::db
        Mongo["mongoose\nMongoDB\nProduct reviews"]:::db
    end

    subgraph SECURITY["Security Controls Layer"]
        Winston["Winston 3.16.0\nConsole transport only\nSimple format - not structured JSON"]
        Prometheus["prom-client\nMetrics exposed at /metrics\nNo auth"]:::risk
    end

    Angular -->|"XHR fetch · REST JSON"| Express
    Express --> Helmet
    Express --> JWT
    Express --> CORS
    Express --> RateLimit
    Express --> Multer
    Express --> Finale
    Express --> Winston
    Express --> Prometheus
    Finale -->|"SQL · Sequelize ORM"| Sequelize
    Sequelize -->|"SQLite file I/O"| SQLiteDB
    Express -->|"mongoose TCP"| Mongo
```

### 2.4 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ⚠️ Partial | Express serves as combined API gateway + app server; no dedicated gateway layer |
| BFF (Backend For Frontend) | ❌ No | SPA directly calls backend; JWT stored in localStorage |
| Defense in Depth | ❌ No | Single container; no WAF; minimal header security; intentionally thin defense |
| Separation of Concerns | ⚠️ Partial | Route handlers separated into `/routes/`; security logic mixed into `lib/insecurity.ts` |
| Least Privilege | ⚠️ Partial | Container runs as UID 65532 (good); CORS is wildcard; login SQL runs as full DB user |
| Secrets Management | ❌ No | Private key hardcoded in source; HMAC secret hardcoded; cookie secret hardcoded |
| Network Segmentation | ❌ No | Single container, no network policies; /ftp, /logs, /encryptionkeys all on same port |
| Secure Defaults | ❌ No | MD5 passwords; CORS wildcard; no CSRF; helmet incomplete; by-design insecure |

#### Trust Model Evaluation

The application does not implement a meaningful trust model. All requests arrive on port 3000 with no enforced TLS, no WAF, and CORS configured to allow all origins. Trust is established solely through JWT bearer tokens, but the private key used to sign those tokens is embedded in source code, rendering the trust model void — any party with access to the repository can forge admin-level JWTs. The application does not fail closed: absence of authorization middleware on some routes (e.g., `PUT /api/Products/:id`) is intentional. There is no implicit trust boundary between the FTP file system, log files, and the API — all are served on the same unauthenticated HTTP port.

#### Authentication & Authorization Architecture

Authentication uses RS256-signed JWTs issued on successful login, with the private key hardcoded in `lib/insecurity.ts:23`. The signing key is a 1024-bit RSA key (considered weak; minimum recommended is 2048-bit). Google OAuth2 is available as an alternative login path with an explicit redirect URI allowlist. 2FA (TOTP) is optionally available per user.

Authorization is distributed across route middleware (not centralized): `isAuthorized()` enforces JWT presence; `isAccounting()` and `isDeluxe()` check role fields in the token payload. There is no server-side session binding — the role is trusted from the token, which can be forged given the public private key. The `denyAll()` middleware correctly blocks some operations but is not applied consistently. Direct object references are used throughout (e.g., basket IDs, user IDs in URLs) without server-side ownership verification.

#### Key Architectural Risks

| # | Structural Risk | Impact if Exploited | Linked Threats |
|---|----------------|---------------------|----------------|
| 1 | JWT private key in source code | Any actor with code access can forge any role or identity | T-002, T-008 |
| 2 | Mixed parameterized + raw SQL in same ORM layer | SQL injection in critical auth paths (login, search) | T-001 |
| 3 | No CORS restrictions + JWT in localStorage | XSS can steal tokens; any site can make credentialed API calls | T-006, T-007, T-016 |
| 4 | File I/O, XML parsing, and VM execution without sandboxing | Path traversal, XXE, RCE via single endpoints | T-003, T-004, T-015 |
| 5 | All dangerous endpoints on same HTTP port as public SPA | No network segmentation; /metrics, /logs, /encryptionkeys all public | T-013, T-014 |

#### Overall Architecture Security Rating

🔴 **Critical Gaps** — The architecture contains fundamental cryptographic failures (hardcoded private key, MD5 hashing), unauthenticated RCE and SQL injection vectors, and absent security controls (no CORS restrictions, no CSRF protection, no TLS enforcement, no secrets management). While structural elements such as non-root containers and route separation provide a partial foundation, the combined severity of the identified cryptographic and injection flaws means the application offers no meaningful security guarantee in any deployment context.

---

## 3. Security-Relevant Use Cases

These sequence diagrams document security-critical flows, showing both normal operation and potential attack vectors for each key security domain.

### 3.1 Authentication Flow (Normal + Attack)

```mermaid
sequenceDiagram
    participant User
    participant Angular as Angular SPA
    participant API as Express API
    participant DB as SQLite

    User->>Angular: Enter email + password
    Angular->>API: POST /rest/user/login {"email":"...","password":"..."}
    Note over API: No rate limiting on this endpoint!
    API->>DB: SELECT * FROM Users WHERE email='${email}' AND password='${md5(pw)}'
    Note over DB: Raw SQL - SQL injection here
    DB-->>API: User row or empty
    alt SQL injection attack
        User->>Angular: email = "' OR 1=1--"
        Angular->>API: POST /rest/user/login {email:"' OR 1=1--"}
        API->>DB: SELECT * FROM Users WHERE email='' OR 1=1--' AND ...
        DB-->>API: First user row (admin)
        API-->>Angular: JWT token for admin
    end
    alt Normal login
        DB-->>API: Matching user
        API->>API: security.authorize(user) -- signs JWT with hardcoded private key
        API-->>Angular: {token, bid, umail}
        Angular->>Angular: localStorage.setItem("token", jwt)
    end
```

### 3.2 JWT Forgery Attack (Hardcoded Private Key)

```mermaid
sequenceDiagram
    participant Attacker
    participant GitHub as Source Code Repository
    participant API as Express API

    Attacker->>GitHub: Clone repo or read lib/insecurity.ts
    GitHub-->>Attacker: RSA private key (line 23)
    Attacker->>Attacker: jwt.sign({data:{role:"admin",email:"x@x.com"}}, privateKey, {algorithm:"RS256"})
    Attacker->>API: GET /api/Users Authorization: Bearer forgedAdminJWT
    Note over API: expressJwt verifies with publicKey - signature valid!
    API-->>Attacker: 200 OK - Full user list with emails and MD5 hashes
    Attacker->>API: PUT /api/Products/1 Authorization: Bearer forgedAdminJWT
    API-->>Attacker: 200 OK - Product modified
```

### 3.3 File Upload Security Flow (XXE + ZipSlip)

```mermaid
sequenceDiagram
    participant Attacker
    participant API as Express API
    participant FS as File System

    Attacker->>API: POST /file-upload Content-Type: multipart [evil.xml]
    Note over API: checkFileType() checks extension only - .xml passes
    API->>API: handleXmlUpload() - libxml.parseXml(data, {noent: true})
    Note over API: XXE: noent=true enables entity resolution!
    API->>FS: Resolves file:///etc/passwd
    FS-->>API: File contents
    API-->>Attacker: 410 error body contains file contents

    Attacker->>API: POST /file-upload Content-Type: multipart [evil.zip]
    Note over API: handleZipFileUpload() extracts to uploads/complaints/
    API->>FS: entry.pipe(writeStream("uploads/complaints/" + entry.path))
    Note over FS: ZipSlip: entry.path = "../../ftp/legal.md" traverses directories
    FS-->>API: File written to arbitrary path
```

### 3.4 Input Validation — Search SQL Injection

```mermaid
sequenceDiagram
    participant Attacker
    participant API as Express API
    participant DB as SQLite

    Attacker->>API: GET /rest/products/search?q=')) UNION SELECT ...
    Note over API: criteria = req.query.q (no sanitization)
    API->>DB: SELECT * FROM Products WHERE name LIKE '%')) UNION SELECT...'
    DB-->>API: Union result with injected data
    API-->>Attacker: 200 OK with exfiltrated data (all user emails + MD5 hashes)
```

### 3.5 Authorization and IDOR

```mermaid
sequenceDiagram
    participant UserA
    participant UserB
    participant API as Express API
    participant DB as SQLite

    UserA->>API: POST /rest/user/login
    API-->>UserA: JWT with UserId=1
    UserB->>API: POST /rest/user/login
    API-->>UserB: JWT with UserId=2

    UserB->>API: GET /rest/basket/1 Authorization: Bearer UserB-JWT
    Note over API: isAuthorized() checks JWT validity only
    Note over API: No ownership check: does JWT.UserId == bid?
    API->>DB: SELECT * FROM Baskets WHERE id=1
    DB-->>API: UserA's basket
    API-->>UserB: 200 OK - UserA's basket contents (IDOR)
```

### 3.6 Chatbot Injection

```mermaid
sequenceDiagram
    participant Attacker
    participant API as Express API
    participant Bot as juicy-chat-bot

    Attacker->>API: POST /rest/chatbot/respond {action:"query", query:"..."}
    API->>Bot: bot.factory.run("currentUser('" + user.id + "')")
    Note over Bot: Template injection if user.id contains special chars
    API->>Bot: bot.respond(req.body.query, userId)
    Note over Bot: Query processed without sanitization
    Bot-->>API: Response action = "function", handler = "balanceOf"
    API->>API: botUtils[response.handler](...) - arbitrary function dispatch
    API-->>Attacker: Wallet balance or other user data
```

---

## 4. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them.

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| User credentials (email + MD5 hash) | Restricted | Stored in SQLite Users table; MD5 hashes trivially reversible | T-001, T-002, T-005 |
| RSA private key (JWT signing) | Restricted | Hardcoded in lib/insecurity.ts:23; controls all auth token issuance | T-002 |
| Credit card data (cardNum, expiry) | Restricted | Stored in SQLite Cards table in plaintext | T-001, T-002 |
| User PII (email, address, phone) | Confidential | Address, delivery, profile data in SQLite | T-001, T-008 |
| TOTP secrets | Restricted | 2FA seeds stored in Users.totpSecret; exposed by SQLi | T-001 |
| Session JWTs | Confidential | Bearer tokens stored in browser localStorage; 6h expiry | T-002, T-007, T-016 |
| Access log files | Confidential | HTTP access logs at /support/logs/ with IP, user-agents, request paths | T-013 |
| Encryption keys directory | Confidential | JWT public key and premium.key at /encryptionkeys/ — publicly browsable | T-014 |
| FTP file store | Internal | Files at /ftp/ including legal documents; directory listing enabled | T-015 |
| Application source code (codefixes) | Internal | Challenge code fixes exposed via /api/vulnCodeFixes | T-014 |
| Wallet balances | Confidential | Numeric credit balances per user in SQLite | T-008, T-009 |
| Product data | Public | Product catalog; modification possible without auth on PUT /api/Products/:id | T-009 |

---

## 5. Attack Surface

All identified entry points through which an attacker can interact with the system, including protocol, authentication requirements, and linked threats.

| Entry Point | Protocol/Method | Authentication | Notes | Linked Threats |
|------------|----------------|---------------|-------|----------------|
| POST /rest/user/login | HTTP POST | None | SQLi in email/password fields; no rate limit | T-001, T-005 |
| GET /rest/products/search?q= | HTTP GET | None | SQLi in q parameter; full DB dump possible | T-001 |
| POST /api/Users (register) | HTTP POST | None | User registration; mass assignment risk | T-017 |
| POST /file-upload | HTTP POST | JWT | XXE + ZipSlip; extension-only type check | T-004, T-015 |
| POST /b2b/v2/orders | HTTP POST | JWT | VM sandbox execution; RCE risk | T-003 |
| GET /ftp/:file | HTTP GET | None | Directory listing + file download; path traversal | T-015 |
| GET /encryptionkeys/:file | HTTP GET | None | JWT public key + premium.key exposed | T-014 |
| GET /support/logs/:file | HTTP GET | None | Access log disclosure (IPs, request paths) | T-013 |
| GET /api-docs | HTTP GET | None | Full Swagger API documentation exposed | T-020 |
| GET /metrics | HTTP GET | None | Prometheus metrics without auth (request counts, timing) | T-013 |
| GET /api/Users | HTTP GET | JWT | User list; IDOR on /api/Users/:id | T-008 |
| GET /rest/basket/:bid | HTTP GET | JWT | IDOR — no ownership check; any basket by ID | T-008 |
| GET /rest/chatbot/* | HTTP GET/POST | JWT | Chatbot query injection | T-018 |
| PUT /api/Products/:id | HTTP PUT | None | Product tampering — auth middleware commented out | T-009 |
| POST /profile/image/url | HTTP POST | JWT | SSRF via URL-based profile image upload | T-019 |
| GET /rest/user/reset-password | HTTP POST | None | Security question reset; HMAC with hardcoded key | T-010 |
| POST /rest/user/change-password | HTTP POST | JWT | Password in query string (URL exposure) | T-021 |
| WebSocket (/socket.io) | WebSocket | None | Challenge notifications; no auth required | T-022 |

---

## 6. Trust Boundaries

Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk.

The overall trust model is severely compromised: the JWT private key is in source code (eliminating the cryptographic trust anchor), CORS is fully open (eliminating the same-origin protection boundary), and critical file paths are unauthenticated (eliminating the network boundary for sensitive data).

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|----------------------|-------------|----------------|
| TB-1 | Internet to Application | Any internet user | Express API port 3000 | None (no TLS enforcement, no WAF, no IP filtering for general routes) | No TLS enforcement; no rate limiting on login | T-001, T-005, T-006 |
| TB-2 | Anonymous to Authenticated | Unauthenticated request | JWT-protected routes | `security.isAuthorized()` — express-jwt validates JWT signature against publicKey | Private key in source code; algorithm confusion risk in old express-jwt | T-002, T-007 |
| TB-3 | Authenticated to Admin | Customer JWT | Admin-only operations | Role field in JWT payload: `role === "admin"` | Role is in JWT; JWT can be forged from hardcoded private key | T-002, T-009 |
| TB-4 | Application to Data Tier | Express route handlers | SQLite database | Sequelize ORM connection (no credentials for SQLite) | Raw SQL in login + search routes bypasses ORM protection | T-001, T-011 |

**TB-1 note:** The /ftp/, /support/logs/, and /encryptionkeys/ directories are served directly over the same unauthenticated HTTP port as the public SPA with no access control layer. These represent an absent enforcement boundary.

**TB-2 note:** `express-jwt` version 0.1.3 (released ~2012) is missing critical security features available in modern versions including algorithm restriction, token revocation, and proper error handling.

---

## 7. Identified Security Controls

**Critical gaps summary:** The five most severe control gaps are: (1) no secrets management — private key, HMAC key, and cookie secret all hardcoded in source; (2) no parameterized queries in critical auth paths (login, search); (3) CORS configured as full wildcard with no origin restrictions; (4) passwords stored as unsalted MD5 rather than any modern password hashing algorithm; (5) no CSRF protection for state-changing operations. These gaps make the application trivially exploitable by any attacker with network access.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness |
|--------|---------|---------------|--------------|
| IAM | JWT-based authentication | [lib/insecurity.ts:54-56](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:54) — express-jwt 0.1.3, RS256 | 🔶 Weak — ancient library, hardcoded key |
| IAM | Google OAuth2 login | [config/default.yml:58-73](vscode://file//home/mrohr/juice-shop/config/default.yml:58) — explicit redirect allowlist | ⚠️ Partial — no PKCE; allowlist present |
| IAM | 2FA / TOTP | [routes/2fa.ts](vscode://file//home/mrohr/juice-shop/routes/2fa.ts) — totp-generator; optional per user | ⚠️ Partial — optional not enforced for sensitive accounts |
| Authorization | Role-based access control | [lib/insecurity.ts:156-176](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:156) — isAuthorized, isAccounting, isDeluxe | 🔶 Weak — role in JWT, key in source |
| Authorization | Resource-level access (IDOR prevention) | server.ts route middleware | ❌ Missing — basket ownership not verified |
| Authorization | Admin action protection | `security.denyAll()` on most PUT/DELETE | ⚠️ Partial — PUT /api/Products/:id deliberately unauthenticated |
| Data Protection | Password hashing | [lib/insecurity.ts:43](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:43) — `crypto.createHash('md5')` | ❌ Missing — MD5 is not a password hash function |
| Data Protection | Credit card storage | [models/card.ts](vscode://file//home/mrohr/juice-shop/models/card.ts) — Sequelize model | ❌ Missing — plaintext storage, no encryption at rest |
| Data Protection | TLS/HTTPS enforcement | [server.ts](vscode://file//home/mrohr/juice-shop/server.ts) — no TLS code | ❌ Missing — HTTP only at application level |
| Input Validation | XML input validation | [routes/fileUpload.ts:83](vscode://file//home/mrohr/juice-shop/routes/fileUpload.ts:83) — libxmljs2 | ❌ Missing — XXE enabled (noent: true by design) |
| Input Validation | SQL query parameterization | [routes/login.ts:34](vscode://file//home/mrohr/juice-shop/routes/login.ts:34), [routes/search.ts:23](vscode://file//home/mrohr/juice-shop/routes/search.ts:23) | ❌ Missing — raw SQL string interpolation |
| Input Validation | File upload validation | [routes/fileUpload.ts:67](vscode://file//home/mrohr/juice-shop/routes/fileUpload.ts:67) — extension check | 🔶 Weak — extension only, no MIME check |
| Audit & Logging | HTTP access logging | [server.ts:329-338](vscode://file//home/mrohr/juice-shop/server.ts:329) — morgan combined format | ⚠️ Partial — logs to file, not structured JSON; publicly accessible |
| Audit & Logging | Application error logging | [lib/logger.ts](vscode://file//home/mrohr/juice-shop/lib/logger.ts) — Winston console transport | 🔶 Weak — console only, simple format, no centralized sink |
| Audit & Logging | Security event logging | [routes/*.ts](vscode://file//home/mrohr/juice-shop/routes) — no security event logging | ❌ Missing — failed auth, privilege escalation not logged |
| Infrastructure | Container non-root | [Dockerfile:39](vscode://file//home/mrohr/juice-shop/Dockerfile:39) — USER 65532 | ✅ Adequate — distroless image, non-root UID |
| Infrastructure | Container image hardening | [Dockerfile:23](vscode://file//home/mrohr/juice-shop/Dockerfile:23) — gcr.io/distroless/nodejs24-debian13 | ⚠️ Partial — distroless (good), no digest pinning |
| Infrastructure | WAF / DDoS protection | No WAF configured | ❌ Missing — no WAF, no DDoS mitigation |
| Infrastructure | Rate limiting | [server.ts:343-347](vscode://file//home/mrohr/juice-shop/server.ts:343) — express-rate-limit on /reset-password + 2FA | 🔶 Weak — absent on login; X-Forwarded-For header trusted without validation |
| Dependency | Lockfile integrity | .npmrc: `package-lock=false` | ❌ Missing — lockfile explicitly disabled |
| Dependency | CI/CD action pinning | [.github/workflows/ci.yml](vscode://file//home/mrohr/juice-shop/.github/workflows/ci.yml) — most SHA-pinned | ⚠️ Partial — coverallsapp/github-action@v2 not SHA-pinned |
| Dependency | SBOM generation | [Dockerfile:21](vscode://file//home/mrohr/juice-shop/Dockerfile:21) — CycloneDX via npm run sbom | ✅ Adequate — SBOM generated during Docker build |
| Security Testing | CI test coverage | [.github/workflows/ci.yml](vscode://file//home/mrohr/juice-shop/.github/workflows/ci.yml) — lint, unit tests, e2e (Cypress) | ✅ Adequate — comprehensive multi-platform test matrix |
| Security Testing | SAST | CodeQL workflow present | ⚠️ Partial — CodeQL analysis in CI; no SAST fail-on-high policy confirmed |
| Frontend Security | Content-Security-Policy | No CSP header set (helmet CSP not called) | ❌ Missing — no CSP |
| Frontend Security | CORS configuration | [server.ts:181-182](vscode://file//home/mrohr/juice-shop/server.ts:181) — `cors()` with no options | ❌ Missing — wildcard CORS |
| Frontend Security | CSRF protection | No csurf or SameSite cookie | ❌ Missing — no CSRF protection |
| Secret Management | Private key storage | [lib/insecurity.ts:23](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:23) — hardcoded RSA key | ❌ Missing — key in source code |
| Secret Management | HMAC secret | [lib/insecurity.ts:44](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:44) — hardcoded string | ❌ Missing — hardcoded in source |

---

## 8. Threat Register

This section documents all identified threats organized by risk level. Risk ratings reflect the attack surface and control gaps identified during reconnaissance.

**Risk methodology:** Risk = Likelihood × Impact. Likelihood considers exploitability, attack complexity, and required privileges. Impact considers confidentiality, integrity, and availability effects on the identified assets. Ratings: Critical, High, Medium, Low.

**Risk Distribution:** Critical: 6 · High: 9 · Medium: 7 · Low: 3 · **Total: 25**
**STRIDE Coverage:** Spoofing: 5 · Tampering: 5 · Repudiation: 2 · Information Disclosure: 7 · Denial of Service: 2 · Elevation of Privilege: 4

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|-----------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | Auth Service / API | Tampering | Unauthenticated SQL injection in both the login route (`routes/login.ts:34` — email field) and the product search route (`routes/search.ts:23` — q parameter). Attacker submits `' OR 1=1--` or UNION SELECT payloads to extract all users, emails, MD5 hashes, credit card numbers, and TOTP secrets from SQLite. No input sanitization, no parameterized queries in these critical paths. (CWE-89) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — raw SQL string interpolation with user input | [M-002](#m-002) |
| <a id="t-002"></a>T-002 | Auth Module | Spoofing | The RSA private key for JWT signing is hardcoded in `lib/insecurity.ts:23` and committed to the public GitHub repository. Any party can read this key and use `jwt.sign({data:{role:"admin"}}, privateKey, {algorithm:"RS256"})` to forge arbitrary JWTs with any role. This bypasses all authentication and authorization controls in the application. (CWE-321) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | RS256 algorithm (only weak due to key exposure); express-jwt verifies signature | [M-003](#m-003) |
| <a id="t-003"></a>T-003 | API Gateway (B2B) | Elevation of Privilege | Authenticated users can POST to `/b2b/v2/orders` with a crafted `orderLinesData` field. The field is passed directly to `vm.runInContext('safeEval(orderLinesData)', sandbox)` (`routes/b2bOrder.ts:23`). The Node.js VM module does not provide true isolation; prototype pollution or known sandbox escape techniques can achieve server-side code execution. (CWE-94) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT authentication required for /b2b/v2 routes; vm timeout (2s) limits DoS | [M-004](#m-004) |
| <a id="t-004"></a>T-004 | File Handling | Information Disclosure | File upload endpoint (`POST /file-upload`) passes XML files to `libxml.parseXml(data, { noent: true, nocdata: true })` (`routes/fileUpload.ts:83`). The `noent: true` option enables external entity resolution, allowing XXE attacks to read server-side files (e.g., `/etc/passwd`, application config) and potentially trigger SSRF to internal services. (CWE-611) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT required for upload; file type check by extension only | [M-004](#m-004) |
| <a id="t-005"></a>T-005 | Auth Module | Information Disclosure | Passwords are stored as unsalted MD5 hashes (`lib/insecurity.ts:43`: `crypto.createHash('md5').update(data).digest('hex')`). MD5 is a general-purpose hash function, not a password hash. Common passwords can be reversed via rainbow tables in milliseconds. Combined with SQLi (T-001), all user passwords are effectively exposed. (CWE-916) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Passwords not returned in API responses (exclude list in finale); MD5 stored | [M-001](#m-001) |
| <a id="t-006"></a>T-006 | API Gateway | Information Disclosure | CORS is configured as a wildcard with `app.use(cors())` and no options (`server.ts:181-182`). This allows any origin to make cross-site requests. Combined with JWT stored in `localStorage` (readable by XSS), any malicious site can make authenticated API calls if the user visits it while logged in. (CWE-942) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — CORS is wildcard by design | [M-005](#m-005) |
| <a id="t-007"></a>T-007 | Auth Module | Spoofing | The `express-jwt` library is version 0.1.3, released circa 2012. Modern express-jwt (v8+) added mandatory algorithm restriction (`algorithms` option). The old version does not enforce algorithm restrictions and may be vulnerable to algorithm confusion attacks (e.g., switching RS256 to HS256 and signing with the public key as an HMAC secret). (CWE-347) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | RS256 configured; public key readable from /encryptionkeys/ | [M-006](#m-006) |
| <a id="t-008"></a>T-008 | API Gateway | Elevation of Privilege | Insecure Direct Object Reference on multiple endpoints: `GET /rest/basket/:bid` checks only that a JWT is present — not that the JWT's UserId matches the basket owner (`server.ts:355`). An authenticated attacker can enumerate other users' baskets, addresses, wallets, and orders by changing numeric IDs in the URL. (CWE-639) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT authentication required for basket access | [M-007](#m-007) |
| <a id="t-009"></a>T-009 | API Gateway | Tampering | `PUT /api/Products/:id` has its authorization middleware commented out in `server.ts:369` (`// app.put('/api/Products/:id', security.isAuthorized())`). Any unauthenticated attacker can modify any product's name, description, price, or image by sending a PUT request. (CWE-284) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None — auth middleware intentionally commented out | [M-007](#m-007) |
| <a id="t-010"></a>T-010 | Auth Module | Spoofing | Password reset uses HMAC-SHA256 of the security answer (`lib/insecurity.ts:44`, `routes/resetPassword.ts:41`), but the HMAC key is hardcoded as `'pa4q****'` in source. An attacker who knows a user's security question and has the HMAC key can precompute valid answers. Security questions are inherently weak (guessable from social media). (CWE-640) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Rate limiting on /rest/user/reset-password (100/5min); HMAC used (vs plaintext) | [M-006](#m-006), [M-003](#m-003) |
| <a id="t-011"></a>T-011 | File Handling | Tampering | ZIP file upload in `handleZipFileUpload` (`routes/fileUpload.ts:40-49`) extracts archive entries using `uploads/complaints/ + entry.path` as the destination without fully validating the path. The check `absolutePath.includes(path.resolve('.'))` may be bypassable with crafted paths on some OS configurations, enabling ZipSlip to write files to arbitrary locations including overwriting application files. (CWE-22) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT required for /file-upload; partial path check `absolutePath.includes(path.resolve('.'))` | [M-004](#m-004) |
| <a id="t-012"></a>T-012 | Frontend SPA | Tampering | Multiple Angular components use `[innerHTML]` binding with user-controlled content from product reviews and user-provided names (welcome-banner, track-result). The `sanitize-html` version 1.4.2 used in the backend is outdated (known bypasses); the `sanitizeLegacy` function (`lib/insecurity.ts:61`) uses a weak regex that can be bypassed. Stored XSS via product reviews or usernames. (CWE-79) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | sanitize-html (outdated); sanitizeLegacy regex (bypassable by design) | [M-008](#m-008) |
| <a id="t-013"></a>T-013 | API Gateway | Information Disclosure | Application logs are accessible at `/support/logs/` with full directory listing enabled (`server.ts:281`). Prometheus metrics are exposed at `/metrics` without authentication. Combined, these reveal HTTP access logs (source IPs, user agents, request paths including JWT fragments), application performance metrics, and request patterns to any unauthenticated visitor. (CWE-532) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Logs rotate daily; log files accessed via HTTP (not direct shell) | [M-009](#m-009) |
| <a id="t-014"></a>T-014 | API Gateway | Information Disclosure | The `/encryptionkeys/` directory is publicly browsable and serves the JWT public key (`jwt.pub`) and `premium.key` without authentication (`server.ts:277-278`). Exposing the JWT public key enables algorithm confusion attacks (T-007). The premium.key file may expose challenge-related secrets. (CWE-538) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Public key is inherently public; challenge design requires exposure | [M-009](#m-009) |
| <a id="t-015"></a>T-015 | File Handling | Information Disclosure | The `/ftp/` directory is publicly browsable without authentication (`server.ts:269-270`, `serveIndex` middleware). Users can enumerate and download all files in the FTP store including `legal.md`, complaint attachments, and any files written via ZipSlip (T-011). (CWE-548) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | robots.txt disallows /ftp (no enforcement); quarantine subdirectory | [M-009](#m-009) |
| <a id="t-016"></a>T-016 | Frontend SPA | Information Disclosure | The Angular SPA stores the JWT bearer token in `localStorage`. Any JavaScript running on the page (including XSS payloads) can read `localStorage.getItem('token')` and exfiltrate the session token. Combined with wildcard CORS (T-006), this enables cross-site session hijacking. (CWE-922) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT has 6h expiry; localStorage is accessible to same-origin scripts only | [M-010](#m-010) |
| <a id="t-017"></a>T-017 | Auth Module | Elevation of Privilege | User registration at `POST /api/Users` accepts a `role` field in the request body (masse assignment via finale-rest auto-generated CRUD). An attacker can register a new account with `{"email":"...", "password":"...", "role":"admin"}`, creating an admin user without administrator credentials. (CWE-915) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | `verify.registerAdminChallenge()` middleware checks and logs this (by design) | [M-007](#m-007) |
| <a id="t-018"></a>T-018 | Chatbot | Tampering | The chatbot processes `req.body.query` without sanitization through `bot.factory.run()` template execution. The factory run template `currentUser('${user.id}')` injects user ID without escaping. Query input is passed directly to `bot.respond(req.body.query)` which dispatches to `botUtils[response.handler]` — allowing manipulation of bot logic flow to access different user data or trigger unintended functionality. (CWE-74) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT authentication required; rule-based bot (limited attack surface) | [M-011](#m-011) |
| <a id="t-019"></a>T-019 | API Gateway | Information Disclosure | `POST /profile/image/url` allows users to supply a URL for profile image upload (`routes/profileImageUrlUpload.ts`). Without SSRF protection, an attacker can supply internal URLs (`http://169.254.169.254/latest/meta-data/` for cloud IMDS, or internal services) to probe the network from the server's perspective. (CWE-918) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT required; URL must be image (content-type checked per challenge logic) | [M-011](#m-011) |
| <a id="t-020"></a>T-020 | API Gateway | Information Disclosure | Swagger UI is publicly exposed at `/api-docs` without authentication (`server.ts:286`). This provides attackers with a complete, interactive inventory of all API endpoints, request/response schemas, and example payloads — dramatically reducing reconnaissance time. (CWE-200) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Swagger docs are read-only reference | [M-009](#m-009) |
| <a id="t-021"></a>T-021 | Auth Module | Information Disclosure | `POST /rest/user/change-password` accepts `current`, `new`, and `repeat` as **URL query parameters** (not request body) — `routes/changePassword.ts:13-17`. Passwords in query strings are logged in server access logs, appear in browser history, and may be captured by proxy servers and web analytics. (CWE-598) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT required for change-password; passwords not logged by app code (but logged by Morgan) | [M-012](#m-012) |
| <a id="t-022"></a>T-022 | API Gateway | Denial of Service | YAML file upload passes content to `yaml.load()` (js-yaml v3.14 — unsafe schema) in `routes/fileUpload.ts:117`. A crafted YAML bomb (billion laughs attack) with nested aliases causes exponential memory consumption, crashing the Node.js process. The vm.runInContext timeout (2s) provides limited protection, but the YAML parsing itself precedes the VM call. (CWE-400) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT required; yamlBombChallenge detection present; 2s VM timeout | [M-004](#m-004) |
| <a id="t-023"></a>T-023 | API Gateway | Repudiation | Winston logger is configured with console transport only and simple format (not structured JSON) (`lib/logger.ts:8-13`). Security events (auth failures, privilege escalation attempts, mass assignment attempts) are not logged with sufficient context. The access logs at `/support/logs/` are publicly readable (T-013), enabling an attacker to delete or modify evidence. (CWE-778) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Morgan HTTP access logs to file; Winston console logs errors | [M-013](#m-013) |
| <a id="t-024"></a>T-024 | Infrastructure | Denial of Service | No rate limiting on the `/rest/user/login` endpoint. An attacker can conduct unlimited brute-force or credential stuffing attacks. Combined with MD5 password hashing (T-005), this enables both online brute force (unlimited attempts) and offline password cracking (once hashes are extracted via SQLi). (CWE-307) | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | express-rate-limit present on reset-password; login unprotected | [M-014](#m-014) |
| <a id="t-025"></a>T-025 | Infrastructure | Repudiation | No HSTS header is set; Helmet CSP is not called; no Referrer-Policy or Permissions-Policy headers are configured (`server.ts:185-192`). Absence of HSTS means browsers do not enforce HTTPS, enabling protocol downgrade to HTTP. Absence of CSP removes the primary defense against XSS content injection. | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | helmet.noSniff() and helmet.frameguard() present; X-Powered-By disabled | [M-015](#m-015) |

---

## 9. Critical Findings

The following findings require immediate attention due to their critical risk rating. Each finding links to its recommended mitigation in the [Mitigation Register](#10-mitigation-register).

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-001 — SQL Injection: Login and Search Endpoints

**Scenario:** An attacker sends `POST /rest/user/login` with `{"email":"' OR 1=1--", "password":"x"}`. The query `SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = ...` returns the first user row (admin). An attacker can also send `GET /rest/products/search?q=')) UNION SELECT id,email,password,role,4,5,6,7,8,9,10 FROM Users--` to extract the entire Users table. Both endpoints are unauthenticated. Files: [routes/login.ts:34](vscode://file//home/mrohr/juice-shop/routes/login.ts:34), [routes/search.ts:23](vscode://file//home/mrohr/juice-shop/routes/search.ts:23).

**Current state:** Raw SQL string interpolation with unescaped user input in both login and search. No parameterized queries, no ORM escaping, no input validation on these paths.

**Violated Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Use parameterized queries for all database access

→ **Mitigation:** [M-002 — Parameterize All SQL Queries](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-002 — Hardcoded RSA Private Key for JWT Signing

**Scenario:** An attacker reads `lib/insecurity.ts:23` from the public GitHub repository, extracts the full RSA 1024-bit private key, and calls `jwt.sign({data:{email:"forger@x.com", role:"admin"}}, stolenPrivateKey, {algorithm:"RS256", expiresIn:"365d"})`. The resulting token passes all `isAuthorized()` checks and `isAccounting()` checks, granting full admin access to every protected endpoint in the application. File: [lib/insecurity.ts:23](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:23).

**Current state:** 1024-bit RSA private key is a literal string constant on line 23 of insecurity.ts, committed to the public GitHub repository since the project's inception.

**Violated Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets MUST be stored in a dedicated secret manager, [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — Validate OAuth token claims

→ **Mitigation:** [M-003 — Remove Hardcoded RSA Private Key from Source Code](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-003 — Remote Code Execution: B2B Order vm.runInContext

**Scenario:** An authenticated attacker sends `POST /b2b/v2/orders` with `{"orderLinesData":"...sandbox escape payload..."}`. The payload is passed to `vm.runInContext('safeEval(orderLinesData)', sandbox, {timeout:2000})`. The Node.js VM module is not a security boundary — standard prototype chain attacks (e.g., `this.constructor.constructor('return process')()`) can escape the sandbox and execute arbitrary OS commands on the server. File: [routes/b2bOrder.ts:23](vscode://file//home/mrohr/juice-shop/routes/b2bOrder.ts:23).

**Current state:** User-controlled string passed to `vm.runInContext` with only a 2-second timeout as mitigation. The `notevil` safeEval provides limited protection but node:vm is not a security sandbox.

**Violated Requirements:** [IV-003](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) — Restrict and validate object graphs during deserialization

→ **Mitigation:** [M-004 — Disable Code Evaluation in B2B and XML/YAML Parsing](#m-004)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-004 — XML External Entity (XXE) Injection

**Scenario:** An attacker uploads an XML file containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to `POST /file-upload`. The parser resolves the entity, and the file content is returned in the error response body: `B2B customer complaints...deprecated...: [file content]`. Network-accessible SSRF is also possible via `http://` entities. File: [routes/fileUpload.ts:83](vscode://file//home/mrohr/juice-shop/routes/fileUpload.ts:83).

**Current state:** `libxml.parseXml(data, { noent: true })` — external entity resolution explicitly enabled. JWT authentication required for upload endpoint.

**Violated Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — Harden XML parsers to prevent XXE attacks

→ **Mitigation:** [M-004 — Disable Code Evaluation in B2B and XML/YAML Parsing](#m-004)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-005 — MD5 Password Hashing

**Scenario:** When combined with SQL injection (T-001), an attacker extracts all MD5 password hashes from the Users table. MD5 hashes of common passwords are reversible in milliseconds using online rainbow tables (e.g., crackstation.net). Passwords such as `admin123` (admin default), `password`, `qwerty` will be recovered immediately. This enables mass account takeover. File: [lib/insecurity.ts:43](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:43), [models/user.ts:77](vscode://file//home/mrohr/juice-shop/models/user.ts:77).

**Current state:** `crypto.createHash('md5').update(data).digest('hex')` — unsalted MD5, no iterations, no adaptive cost factor.

**Violated Requirements:** [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Do not store user credentials using weak hashing

→ **Mitigation:** [M-001 — Replace MD5 with bcrypt/Argon2 for Password Hashing](#m-001)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-006 — Wildcard CORS Configuration

**Scenario:** An attacker hosts a malicious website that makes JavaScript XHR requests to the Juice Shop API. Because `Access-Control-Allow-Origin: *` is returned for all requests (`server.ts:182`), the browser allows cross-origin reads. A victim browsing the malicious site while logged into Juice Shop has their API session accessible. If XSS is achieved (T-012), the localStorage JWT can be exfiltrated to any attacker-controlled origin. File: [server.ts:181-182](vscode://file//home/mrohr/juice-shop/server.ts:181).

**Current state:** `app.options('*', cors()); app.use(cors())` — no origin restriction, no credential restriction, applicable to all routes.

**Violated Requirements:** [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) — Configure CORS restrictively; never use wildcard for authenticated APIs

→ **Mitigation:** [M-005 — Restrict CORS to Explicit Origin Allowlist](#m-005)

---

## 10. Mitigation Register

Prioritized measures to address identified threats. Each mitigation references the threats it addresses and includes concrete implementation guidance.

### <a id="m-001"></a>M-001 · Replace MD5 with bcrypt/Argon2 for Password Hashing

**Addresses:** [T-005](#t-005)
**Fulfills Requirements:** [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Password storage requirements
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** MD5 is a general-purpose hash function with no work factor. A single modern GPU can compute billions of MD5 hashes per second. All stored passwords are trivially recoverable once the hash database is extracted via SQL injection. This is the most impactful credential security fix available.

**How:**
1. Install bcrypt: `npm install bcrypt` (or argon2: `npm install argon2`)
2. Replace `hash()` in `lib/insecurity.ts:43` — change from MD5 to bcrypt:
3. Update login query in `routes/login.ts` to load user by email only, then compare with `bcrypt.compare()`
4. Run a migration to rehash all existing passwords on next login (store both until migrated)
5. Update `models/user.ts:77` setter to call the new hash function

```typescript
// BEFORE (lib/insecurity.ts:43)
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// AFTER
import bcrypt from 'bcrypt'
const SALT_ROUNDS = 12
export const hash = async (data: string): Promise<string> => bcrypt.hash(data, SALT_ROUNDS)
export const verifyHash = async (data: string, stored: string): Promise<boolean> => bcrypt.compare(data, stored)
```

```typescript
// BEFORE (routes/login.ts:34 — also fixes T-001)
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'...`)

// AFTER — load user by email only, then bcrypt compare
const user = await UserModel.findOne({ where: { email: req.body.email } })
if (user && await security.verifyHash(req.body.password, user.password)) { /* proceed */ }
```

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), CWE-916

---

### <a id="m-002"></a>M-002 · Parameterize All SQL Queries

**Addresses:** [T-001](#t-001)
**Fulfills Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries for all database access
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** SQL injection in the login and search endpoints allows full database extraction without authentication — all user credentials, credit card data, and TOTP secrets are accessible. This is the most severe unauthenticated vulnerability in the application.

**How:**
1. Fix `routes/login.ts:34` — replace raw SQL with Sequelize `where` clause (parametrized by ORM):
2. Fix `routes/search.ts:23` — replace raw SQL with Sequelize `where` + `Op.like` (parametrized):
3. Audit all other `models.sequelize.query()` calls and replace with Sequelize model methods
4. Enable Sequelize strict mode to warn on any raw query usage

```typescript
// BEFORE (routes/login.ts:34)
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })

// AFTER — Sequelize parameterized (also see M-001 for password comparison change)
UserModel.findOne({ where: { email: req.body.email, deletedAt: null } })
```

```typescript
// BEFORE (routes/search.ts:23)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

// AFTER
import { Op } from 'sequelize'
ProductModel.findAll({
  where: {
    [Op.or]: [
      { name: { [Op.like]: `%${criteria}%` } },
      { description: { [Op.like]: `%${criteria}%` } }
    ],
    deletedAt: null
  },
  order: [['name', 'ASC']]
})
```

**Reference:** [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), CWE-89

---

### <a id="m-003"></a>M-003 · Remove Hardcoded Cryptographic Secrets from Source Code

**Addresses:** [T-002](#t-002), [T-010](#t-010)
**Fulfills Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets in dedicated secret manager, [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — JWT claims validation
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** The RSA private key in source code allows any repository reader to forge admin-level JWTs, bypassing all authentication. The hardcoded HMAC key enables precomputation of valid password reset answers. The cookie parser secret enables session forgery.

**How:**
1. Generate a new 2048-bit (minimum) RSA key pair: `openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -pubout -out public.pem`
2. Load the private key from environment variable: `process.env.JWT_PRIVATE_KEY`
3. Load the HMAC secret from environment variable: `process.env.HMAC_SECRET`
4. Load the cookie parser secret from environment variable: `process.env.COOKIE_SECRET`
5. Configure Docker/Kubernetes secrets injection (never .env files in production)
6. Rotate the current keys immediately — treat them as compromised
7. Add `lib/insecurity.ts` to `.gitleaks.toml` or `truffleHog` exclude for the test-only fake key check

```typescript
// BEFORE (lib/insecurity.ts:22-24)
export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXA...'

// AFTER
export const publicKey = process.env.JWT_PUBLIC_KEY ?? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')
const privateKey = process.env.JWT_PRIVATE_KEY
if (!privateKey) throw new Error('JWT_PRIVATE_KEY environment variable is required')
```

**Reference:** [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), CWE-321

---

### <a id="m-004"></a>M-004 · Disable Code Evaluation in B2B Endpoint and Unsafe Parsing

**Addresses:** [T-003](#t-003), [T-004](#t-004), [T-011](#t-011), [T-022](#t-022)
**Fulfills Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — Harden XML parsers, [IV-003](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) — Restrict deserialization
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** The B2B VM sandbox, XXE-enabled XML parser, YAML bomb parser, and ZipSlip-vulnerable ZIP handler each represent server-side code execution or arbitrary file write paths that can be reached by authenticated users.

**How:**
1. **B2B orders** (`routes/b2bOrder.ts`): Replace dynamic eval with a schema-validated JSON input parser (use `zod` or `joi`); remove `vm.runInContext` entirely
2. **XML upload** (`routes/fileUpload.ts:83`): Change parser options to `{ noent: false, nonet: true }` to disable entity resolution
3. **YAML upload** (`routes/fileUpload.ts:117`): Use `yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })` or `JSON_SCHEMA` (no JS execution)
4. **ZIP upload** (`routes/fileUpload.ts:44`): Validate extracted path strictly with `path.normalize()` and prefix check before writing

```typescript
// BEFORE (routes/fileUpload.ts:83)
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })

// AFTER
const xmlDoc = libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, nocdata: true })
```

```typescript
// BEFORE (routes/fileUpload.ts:44)
entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))

// AFTER
const safeBase = path.resolve('uploads/complaints/')
const destPath = path.resolve(safeBase, fileName)
if (!destPath.startsWith(safeBase + path.sep)) { entry.autodrain(); return }
entry.pipe(fs.createWriteStream(destPath))
```

**Reference:** [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), CWE-611

---

### <a id="m-005"></a>M-005 · Restrict CORS to Explicit Origin Allowlist

**Addresses:** [T-006](#t-006)
**Fulfills Requirements:** [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) — Restrictive CORS with explicit allowlist
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** Wildcard CORS removes the browser's same-origin isolation boundary, enabling any website to read API responses on behalf of an authenticated user.

**How:**
1. Replace `app.use(cors())` with an origin-checked CORS configuration
2. Read allowed origins from config (already available via the `config` module)
3. For authenticated endpoints, set `credentials: true` and explicit origin

```typescript
// BEFORE (server.ts:181-182)
app.options('*', cors())
app.use(cors())

// AFTER
const allowedOrigins = config.get<string[]>('application.corsAllowedOrigins') ?? ['https://demo.owasp-juice.shop']
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true)
    else callback(new Error('Not allowed by CORS'))
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))
```

**Reference:** [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html), CWE-942

---

### <a id="m-006"></a>M-006 · Upgrade express-jwt and Enforce Algorithm Restriction

**Addresses:** [T-007](#t-007), [T-010](#t-010)
**Fulfills Requirements:** [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — Validate token claims, [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) — Central IdP
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** express-jwt 0.1.3 is a ~14-year-old package with known algorithm confusion vulnerabilities. Modern versions require explicit algorithm specification, preventing attackers from switching to HS256 and signing with the public key.

**How:**
1. `npm install express-jwt@8` (current major version)
2. Update all `isAuthorized()` calls to pass `{ algorithms: ['RS256'] }` explicitly
3. Add `issuer` and `audience` claims to JWT issuance and validation
4. Enable token revocation list (middleware cache) for logout functionality

```typescript
// BEFORE (lib/insecurity.ts:54)
export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)

// AFTER (express-jwt v8 API)
import { expressjwt } from 'express-jwt'
export const isAuthorized = () => expressjwt({
  secret: publicKey,
  algorithms: ['RS256'],
  issuer: 'juice-shop',
  audience: 'juice-shop-users'
})
```

**Reference:** [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html), CWE-347

---

### <a id="m-007"></a>M-007 · Add Resource Ownership Checks and Fix Mass Assignment

**Addresses:** [T-008](#t-008), [T-009](#t-009), [T-017](#t-017)
**Fulfills Requirements:** [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) — Least-privilege RBAC; deny by default, [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) — IDOR prevention
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** IDOR on basket/address/order endpoints allows horizontal privilege escalation. Unauthenticated product modification enables defacement. Mass assignment in user registration enables vertical privilege escalation to admin.

**How:**
1. Add basket ownership middleware: verify `JWT.bid === req.params.bid` before serving basket data
2. Uncomment and enforce `security.isAuthorized()` on `PUT /api/Products/:id` (`server.ts:369`)
3. Add a `allowedFields` list to user registration; strip `role` and `isAdmin` from POST /api/Users body
4. Add resource ownership middleware for addresses, orders, wallets

```typescript
// Add to server.ts (IDOR fix for basket)
app.use('/rest/basket/:bid', security.isAuthorized(), (req, res, next) => {
  const token = security.authenticatedUsers.get(utils.jwtFrom(req))
  if (token?.bid !== parseInt(req.params.bid)) return res.status(403).json({ error: 'Access denied' })
  next()
})

// Add to POST /api/Users handler (mass assignment fix)
app.post('/api/Users', (req, res, next) => {
  delete req.body.role
  delete req.body.isAdmin
  delete req.body.totpSecret
  next()
})
```

**Reference:** [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), CWE-639

---

### <a id="m-008"></a>M-008 · Update sanitize-html and Enforce Output Encoding

**Addresses:** [T-012](#t-012)
**Fulfills Requirements:** [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — Encode user-controlled output; use framework-native binding
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Stored XSS via usernames and product reviews enables session hijacking (combined with localStorage JWT storage), phishing, and arbitrary client-side code execution for all users who view the affected pages.

**How:**
1. Upgrade `sanitize-html` from 1.4.2 to latest 2.x: `npm install sanitize-html@latest`
2. Replace the `sanitizeLegacy` regex-based function with `sanitizeHtml()` for all username/review inputs
3. Replace Angular `[innerHTML]` bindings with text-only bindings `{{ }}` where HTML rendering is not needed
4. Where HTML is needed (product descriptions), use Angular's `DomSanitizer.bypassSecurityTrustHtml()` only after server-side sanitization
5. Add Content-Security-Policy header (see M-015) as defense-in-depth

**Reference:** [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), CWE-79

---

### <a id="m-009"></a>M-009 · Restrict Access to Internal Paths and Sensitive Directories

**Addresses:** [T-013](#t-013), [T-014](#t-014), [T-015](#t-015), [T-020](#t-020)
**Fulfills Requirements:** [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) — Internal endpoints not reachable from public networks, [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) — Deny by default
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Publicly accessible logs, encryption keys, metrics, FTP directory, and API documentation dramatically reduce attack cost by providing free reconnaissance to attackers.

**How:**
1. Add `security.isAuthorized()` middleware before `/support/logs` routes
2. Add `security.isAccounting()` middleware before `/metrics` Prometheus endpoint
3. Remove or restrict `/api-docs` — either add admin auth or disable in production (`NODE_ENV === 'production'`)
4. Restrict `/encryptionkeys/` to serve only the public key (not premium.key) and add authentication
5. Restrict `/ftp/` to authenticated users only, or disable directory listing

```typescript
// server.ts — add auth to sensitive routes
app.use('/support/logs', security.isAuthorized())  // before existing serveLogFiles
app.use('/metrics', security.isAccounting())        // protect Prometheus metrics
if (process.env.NODE_ENV === 'production') {
  app.use('/api-docs', (req, res) => res.status(404).end())
}
```

**Reference:** [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), CWE-538

---

### <a id="m-010"></a>M-010 · Migrate JWT from localStorage to HttpOnly Cookies

**Addresses:** [T-016](#t-016)
**Fulfills Requirements:** [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — Do not store sensitive data in localStorage
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** High

**Why:** JWT tokens in `localStorage` are accessible to any JavaScript on the page. XSS immediately leads to session theft. Moving to HttpOnly cookies makes the token inaccessible to JavaScript.

**How:**
1. On successful login, set the JWT as an HttpOnly, Secure, SameSite=Strict cookie instead of returning it in the response body
2. Update Angular SPA to not store the token — rely on cookie automatic inclusion
3. Enable CSRF protection (see M-012) once moving to cookies
4. Set cookie expiry to match JWT expiry (6h)

```typescript
// routes/login.ts — after token creation
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 6 * 60 * 60 * 1000  // 6 hours in ms
})
```

**Reference:** [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html), CWE-922

---

### <a id="m-011"></a>M-011 · Input Validation and SSRF Protection for Chatbot and URL Upload

**Addresses:** [T-018](#t-018), [T-019](#t-019)
**Fulfills Requirements:** [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) — Validate all external input restrictively
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Chatbot query injection can manipulate bot behavior to access other users' data. SSRF via profile image URL can probe internal cloud metadata services (e.g., AWS IMDS at 169.254.169.254).

**How:**
1. Add chatbot query length limit and character allowlist validation
2. For profile image URL upload: validate URL scheme (only `https://`), hostname against an allowlist, and reject private IP ranges (RFC 1918, 169.254.x.x, ::1)
3. Use an SSRF-safe HTTP client wrapper that blocks redirects to private IP space

```typescript
// routes/profileImageUrlUpload.ts — SSRF prevention
import { URL } from 'url'
const PRIVATE_IP_REGEX = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)/
function isSafeUrl (urlString: string): boolean {
  try {
    const u = new URL(urlString)
    return u.protocol === 'https:' && !PRIVATE_IP_REGEX.test(u.hostname)
  } catch { return false }
}
```

**Reference:** [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), CWE-918

---

### <a id="m-012"></a>M-012 · Move Sensitive Parameters from URL Query Strings to Request Body

**Addresses:** [T-021](#t-021)
**Fulfills Requirements:** [DP-003](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) — Transmit sensitive data in HTTP body not URLs
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Passwords in query strings appear in server access logs, browser history, proxy logs, and referrer headers. The change-password endpoint currently sends `?current=&new=&repeat=` in the URL.

**How:**
1. Update `routes/changePassword.ts` to read from `req.body` instead of `req.query`
2. Update the Angular frontend service to use POST with a JSON body instead of query parameters
3. Verify that Morgan access logging excludes the request body (or configure body redaction)

```typescript
// BEFORE (routes/changePassword.ts:13-17)
const currentPassword = query.current as string
const newPassword = query.new as string

// AFTER
const currentPassword = req.body.current as string
const newPassword = req.body.new as string
```

**Reference:** [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), CWE-598

---

### <a id="m-013"></a>M-013 · Implement Structured Security Event Logging

**Addresses:** [T-023](#t-023)
**Fulfills Requirements:** [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — Log all security-relevant events, [LM-002](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — Structured JSON format
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Without structured security logging, failed authentication attempts, IDOR access, and privilege escalation attempts leave no auditable trail, making incident investigation impossible.

**How:**
1. Update Winston logger to use JSON format: `winston.format.json()`
2. Add a security event logging middleware that records: timestamp, event type, userId, sourceIP, endpoint, outcome
3. Add logging on: failed JWT validation, failed auth, admin action, file upload, password reset

```typescript
// lib/logger.ts — structured JSON logging
export default winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/security.log' })
  ],
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  )
})

// Example security event
logger.warn({ event: 'AUTH_FAILURE', userId: null, email: req.body.email, ip: req.ip, endpoint: '/rest/user/login' })
```

**Reference:** [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), CWE-778

---

### <a id="m-014"></a>M-014 · Add Rate Limiting to Login and Registration Endpoints

**Addresses:** [T-024](#t-024)
**Fulfills Requirements:** [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) — Rate limiting on all externally reachable endpoints
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Without rate limiting on login, brute-force and credential stuffing attacks can run at network speed. The `express-rate-limit` library is already installed and used on /reset-password — extension to /login is trivial.

**How:**
1. Add rate limiter to `/rest/user/login` with a lower limit than reset-password (10-20/5min):
2. Add exponential backoff with account lockout after N failures
3. Fix the `X-Forwarded-For` header trust issue in the existing rate limit config (`server.ts:346`)

```typescript
// server.ts — add before login route registration (server.ts:594)
app.use('/rest/user/login', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts, please try again in 5 minutes'
}))
app.post('/rest/user/login', login())
```

**Reference:** [OWASP DoS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html), CWE-307

---

### <a id="m-015"></a>M-015 · Add Missing Security Headers (HSTS, CSP, Referrer-Policy)

**Addresses:** [T-025](#t-025)
**Fulfills Requirements:** [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) — CSP headers, [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) — HSTS, [WEB-008](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) — Referrer-Policy
**Priority:** <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | **Effort:** Low

**Why:** HSTS prevents protocol downgrade attacks. CSP is the primary browser defense against XSS injection. Referrer-Policy prevents leaking sensitive URL fragments. Helmet 4.x is already installed — these headers just need to be enabled.

**How:**
1. Enable HSTS via helmet: `app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))`
2. Enable CSP via helmet (start in report-only mode):
3. Add Referrer-Policy: `app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }))`

```typescript
// server.ts — add to security middleware block (after line 186)
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],  // Angular requires this initially
    imgSrc: ["'self'", 'data:', 'blob:'],
    connectSrc: ["'self'"],
    reportUri: '/csp-report'
  },
  reportOnly: true  // Start in report-only mode
}))
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }))
```

**Reference:** [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), CWE-693

---

## 11. Out of Scope

Areas deliberately excluded from this assessment, including items requiring separate analysis.

- **Intentional vulnerabilities as training challenges:** The application contains hundreds of documented intentional vulnerabilities implemented as CTF challenges. This threat model focuses on the structural security architecture and critical vulnerability classes, not enumeration of every individual challenge. The `data/static/codefixes/` directory contains reference fixes for challenge vulnerabilities.
- **Frontend Angular component security audit:** A full audit of all Angular components for DOM XSS patterns is beyond this assessment's scope. Key patterns were identified (innerHTML bindings, stored XSS via reviews).
- **MongoDB product reviews security:** NoSQL injection in the MongoDB review layer was not fully analyzed. The MongoDB connection configuration (host, port, authentication) was not found in the reviewed files.
- **WebSocket (Socket.io) protocol security:** The WebSocket endpoint for challenge notifications uses no authentication (as identified in T-022). A dedicated WebSocket security audit was not performed.
- **Third-party dependencies vulnerability scanning:** `WITH_SCA=false` was specified; no automated CVE scanning of the 71 direct dependencies was performed. Given the application intentionally uses outdated packages, a full SCA scan is strongly recommended.
- **Crypto challenges and Web3 components:** The NFT minting routes (`routes/nftMint.ts`, `routes/web3Wallet.ts`) and related blockchain integration were not analyzed.
- **Deployed instances:** This analysis was performed on source code only. Runtime security configuration of any deployed instances (reverse proxy TLS, WAF rules, network policies) is out of scope.
- **GDPR/data protection compliance:** The data erasure feature was not audited for completeness or GDPR compliance.
