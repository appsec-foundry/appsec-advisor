# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-08T21:35:00Z |
| Analysis Duration | n/a |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Agent Models | all agents: claude-sonnet-4-6 |
| Input Tokens | unavailable |
| Output Tokens | unavailable |
| Cache Read Tokens | unavailable |
| Cache Write Tokens | unavailable |
| Estimated Cost | unavailable |
| Context Sources | Requirements YAML (remote: http://127.0.0.1:8000/appsec-requirements-example.yaml) |

> ℹ Token and cost data are not accessible at agent runtime. Check the Anthropic Console for usage details of this session.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Containers](#22-containers)
   - [2.3 Technology Architecture](#23-technology-architecture)
   - [2.4 Security Architecture Assessment](#24-security-architecture-assessment)
3. [Security-Relevant Use Cases](#3-security-relevant-use-cases)
4. [Assets](#4-assets)
5. [Attack Surface](#5-attack-surface)
6. [Trust Boundaries](#6-trust-boundaries)
7. [Identified Security Controls](#7-identified-security-controls)
   - [7b. Requirements Compliance](#7b-requirements-compliance)
8. [Threat Register](#8-threat-register)
9. [Critical Findings](#9-critical-findings)
10. [Mitigation Register](#10-mitigation-register)
11. [Out of Scope](#11-out-of-scope)

---

## 1. System Overview

**OWASP Juice Shop** (v19.2.1) is an intentionally vulnerable web application used as a training, demonstration, and exercise tool for web application security. It simulates a modern e-commerce platform selling juice products and deliberately contains a wide range of security vulnerabilities across all OWASP Top 10 categories. It is developed and maintained by the OWASP Foundation.

**Important Note:** This is a security training tool, not a production application. All vulnerabilities identified in this report are **intentional by design** for educational purposes. However, this threat model is produced as if the application were being assessed for production deployment, to demonstrate realistic findings.

**Users:** Security researchers, students, penetration testers, security trainers.

**Deployment:** Docker container (distroless Node.js 24, UID 65532), exposed on port 3000. Available on Heroku, Railway, and other cloud platforms.

**Complexity Tier: Moderate** — Single deployable unit (monolith) with a distinct Angular SPA frontend served from the same Express server, a separate SQLite database, MongoDB-style embedded collections (MarsDB), plus external Google OAuth integration. Multiple functional components with distinct security responsibilities justify the Moderate classification.

**Tech Stack:** Node.js 24 / Express 4.22 backend, Angular 20 frontend (served as SPA), SQLite 5 via Sequelize 6 ORM, JWT authentication (RS256), Google OAuth 2.0 (implicit flow — deprecated), Prometheus metrics, Winston logging.

**Context Sources Used:** Security requirements fetched from http://127.0.0.1:8000/appsec-requirements-example.yaml. No external context endpoint configured. No business context file found.

**Overall Security Impression:** The application contains an extraordinary density of critical and high-severity vulnerabilities: SQL injection in authentication (authentication bypass), hardcoded RSA private key in source code, MD5 password hashing, unauthenticated admin endpoints, XXE in file upload, server-side template injection via eval(), SSRF, RCE via vm.runInContext, JWT tokens stored in localStorage, and CORS allowing all origins. This represents a worst-practice application for educational purposes. For any production deployment scenario, the application would receive a **Critical** security rating with no redeeming security architecture.

---

## 2. Architecture Diagrams

### 2.1 System Context

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["🌐 Public Internet · untrusted"]
        USER["Anonymous User\nBrowser / HTTP Client"]:::person
        ATTACKER["Security Researcher\nPentester / Student"]:::person
    end

    subgraph APP_ZONE["🔒 Application Zone · Docker Container"]
        JS["OWASP Juice Shop\nExpress 4.22 + Angular 20\nNode.js 24\nDocker · distroless · UID 65532"]:::risk
    end

    subgraph EXTERNAL_SVC["🌐 External Services"]
        GOOGLE["Google OAuth 2.0\nIdentity Provider\napi.googleapis.com"]:::external
        ETHERS["Web3/Ethereum\nethers.js ^6.16\nBlockchain"]:::external
    end

    subgraph DATA_TIER["🔐 Data Tier · restricted"]
        SQLITE[("SQLite Database\nSequelize 6\ndata/juiceshop.sqlite\nLocal file")]:::db
        MARSDB[("MarsDB Collections\norders + reviews\nIn-memory/file store")]:::db
    end

    USER -->|"HTTP · port 3000 (no TLS in app)"| JS
    ATTACKER -->|"HTTP/API attacks · port 3000"| JS
    JS -->|"OAuth implicit flow (DEPRECATED)\n#access_token in URL"| GOOGLE
    JS -->|"Web3 RPC calls"| ETHERS
    JS -->|"SQL · file I/O"| SQLITE
    JS -->|"MarsDB queries"| MARSDB

    %% Trust Boundary Key:
    %% 🌐 Public Internet → 🔒 Application Zone: No WAF, no TLS termination at app level
    %% 🔒 Application Zone → 🔐 Data Tier: No network policy, file-level access only
    %% 🔒 Application Zone → 🌐 External Services: HTTPS outbound (OAuth, Web3)
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
        BROWSER["Browser\nAngular 20 SPA\nNode.js build"]:::person
    end

    subgraph DMZ["🔶 Express Server · Docker · port 3000"]
        subgraph FRONTEND_LAYER["Frontend Serving"]
            STATIC["Static Files\nAngular SPA dist\nExpress static middleware"]:::system
        end
        subgraph API_LAYER["REST API Layer"]
            REST["REST API\nExpress 4.22 routes/\nNode.js 24"]:::risk
            B2B["B2B API\n/b2b/v2/orders\nExpress 4.22\nJWT required"]:::risk
        end
        subgraph AUTH_ZONE["🛡 Auth Zone"]
            AUTH["Auth Subsystem\nlib/insecurity.ts\nexpress-jwt 0.1.3\njsonwebtoken 0.4.0"]:::risk
        end
        subgraph UPLOAD["File Processing"]
            UPLOAD_H["File Upload Handler\nroutes/fileUpload.ts\nMulter + libxmljs2\nvm sandbox"]:::risk
        end
    end

    subgraph DATA_TIER["🔐 Data Tier · restricted"]
        SQLITE[("SQLite\nSequelize 6\ndata/juiceshop.sqlite")]:::db
        MARSDB[("MarsDB\norders+reviews\nIn-memory")]:::db
    end

    subgraph EXTERNAL["🌐 External"]
        GOOGLE_IDP["Google OAuth IDP\nImplicit flow\napi.googleapis.com"]:::external
    end

    BROWSER -->|"GET / (unauth) · SPA bundle"| STATIC
    BROWSER -->|"POST /rest/user/login · JSON"| REST
    BROWSER -->|"GET/POST /api/* · JWT Bearer"| REST
    BROWSER -->|"POST /file-upload · multipart"| UPLOAD_H
    BROWSER -->|"OAuth implicit flow\n#access_token in URL"| GOOGLE_IDP
    GOOGLE_IDP -->|"access_token in URL fragment"| BROWSER
    REST -->|"JWT validate · RS256"| AUTH
    B2B -->|"JWT validate · RS256"| AUTH
    REST -->|"SQL queries (some raw)"| SQLITE
    REST -->|"MarsDB queries"| MARSDB
    UPLOAD_H -->|"file writes · path traversal risk"| SQLITE
    B2B -->|"POST /b2b/v2/orders · JWT Bearer"| AUTH

    %% Trust Boundary Key:
    %% 🌐 Internet → 🔶 DMZ: No WAF, no TLS, CORS wildcard (*) allows all origins
    %% 🔶 DMZ → 🛡 Auth Zone: JWT RS256 middleware, but express-jwt v0.1.3 (obsolete)
    %% 🔶 DMZ → 🔐 Data Tier: Sequelize ORM, but raw SQL used in login and search
    %% Auth Zone → 🌐 External: Google OAuth implicit flow (deprecated, token in URL)
```

### 2.3 Technology Architecture

```mermaid
graph TD
    subgraph CLIENT["Client Tier · Browser"]
        SPA["Angular 20 SPA\nTypeScript · RxJS\nAngular Material\nBuilt: Node.js 20 build"]
        STORAGE["localStorage\nJWT token stored\nXSS accessible!"]
    end

    subgraph SERVER["Server Tier · Docker · gcr.io/distroless/nodejs24"]
        EXPRESS["Express 4.22\nNode.js 24\nTypeScript compiled\nUID 65532"]
        HELMET["Helmet 4.6\nnoSniff + frameguard\nNo CSP configured!"]
        CORS_MW["CORS middleware\ncors ^2.8.5\nWILDCARD origin!"]
        JWT_MW["JWT Middleware\nexpress-jwt 0.1.3\nRS256 public key"]
        MORGAN["Morgan + Winston\nHTTP access log\nConsole only"]
        PROM["Prometheus\nprom-client 14.2\nUNAUTH /metrics!"]
    end

    subgraph TEMPLATE["Template Engine"]
        HBS["Handlebars 4.2\ndata erasure views"]
        PUG["Pug 3.0\nuserProfile (eval!)"]
    end

    subgraph DATA["Data Tier · File System"]
        SEQUELIZE["Sequelize 6.37\nSQLite dialect"]
        SQLITE[("SQLite 5.1.7\ndata/juiceshop.sqlite\nNo encryption")]
        MARSDB[("MarsDB 0.6.11\nIn-process store\norders/reviews")]
    end

    subgraph CRYPTO["Cryptography"]
        JWT_KEY["RSA-2048 Key Pair\nPRIVATE KEY HARDCODED\nin lib/insecurity.ts!"]
        MD5["MD5 password hash\ncrypto.createHash\nCritically weak!"]
    end

    SPA -->|"HTTP REST · JSON · port 3000"| EXPRESS
    SPA -->|"reads/writes token"| STORAGE
    EXPRESS --> HELMET
    EXPRESS --> CORS_MW
    EXPRESS --> JWT_MW
    EXPRESS --> MORGAN
    EXPRESS --> PROM
    EXPRESS --> HBS
    EXPRESS --> PUG
    JWT_MW -->|"reads public key"| JWT_KEY
    EXPRESS -->|"via Sequelize"| SEQUELIZE
    SEQUELIZE -->|"SQLite file"| SQLITE
    EXPRESS -->|"direct queries"| MARSDB
    EXPRESS -->|"MD5 hash passwords"| MD5
```

### 2.4 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ❌ | No API gateway; all traffic hits Express directly on port 3000 |
| BFF (Backend for Frontend) | ❌ | SPA makes direct API calls; JWT tokens stored in localStorage, not managed by a server-side BFF session |
| Defense-in-depth | ❌ | Single application layer; no WAF, no reverse proxy with security headers in code |
| Separation of concerns | ⚠️ | Routes are modularized but all share one process; DB logic mixed with route handlers |
| Least privilege | ⚠️ | Docker runs as UID 65532 (good), but app-level roles are not consistently enforced (admin endpoints unauthenticated) |
| Secrets management | ❌ | RSA private key and HMAC secret hardcoded in source code (`lib/insecurity.ts`) |
| Network segmentation | ❌ | Single exposed port; no internal network separation; no VPC, no security groups in code |
| Secure defaults | ❌ | CORS wildcard, no CSP, no HSTS, error handler exposes stack traces, MD5 passwords |

#### Trust Model Evaluation

The application has **no coherent trust model**. The DMZ zone accepts unauthenticated traffic to critical endpoints (`/rest/admin/*`, `/metrics`). The JWT middleware is applied inconsistently — some administrative routes lack any auth guard. The CORS policy (`app.use(cors())`) allows requests from any origin with no origin validation, effectively treating all browsers on the internet as trusted peers.

The Data Tier offers no additional protection: the SQLite file is stored locally without encryption, and raw SQL queries (bypassing the ORM) are used in the most security-critical routes (login, search). The Auth Zone is structurally weak: it relies on an obsolete `express-jwt` version (0.1.3, released ~2013, 7 major versions behind) with known security issues, and the private key used to sign tokens is embedded in version-controlled source code.

The system does not implement fail-closed behavior: missing authentication checks default to public access, not denial.

#### Authentication & Authorization Architecture

**Authentication:** JWT RS256 tokens issued at login via `security.authorize()` in `lib/insecurity.ts:56`. Tokens carry user data including role and are stored client-side in `localStorage` (not `HttpOnly` cookies). Token expiry is 6 hours. A second factor (TOTP) is optionally required if `totpSecret` is set.

**Google OAuth:** Uses the **deprecated implicit flow** where the `access_token` appears directly in the URL hash (`#access_token=...`). The Angular router checks for `#access_token=` at `frontend/src/app/app.routing.ts:262`. There is no PKCE, no `state` parameter validation, and no `nonce` validation. The access token is passed to the Google userinfo endpoint and the resulting email is used to auto-register or log in the user — with a password derived from base64-encoding the reversed email address.

**Authorization:** Role-based, with roles: `customer`, `deluxe`, `accounting`, `admin`. The `security.isAuthorized()` middleware validates JWT signatures. The `security.isAccounting()` middleware checks for the `accounting` role. However, `/rest/admin/*` endpoints have no auth middleware applied. The `appendUserId()` middleware binds requests to the authenticated user's ID, but several routes fetch basket/order data by client-supplied ID with no ownership check (IDOR).

#### Key Architectural Risks

| # | Structural Risk | Impact if Exploited | Linked Threats |
|---|----------------|--------------------|--------------------|
| 1 | JWT private key embedded in source code — any developer, CI system, or public fork has the private key | Complete authentication bypass; forge JWT tokens for any user including admin | T-001 |
| 2 | No centralized authorization enforcement — each route independently decides whether to check the JWT; admin endpoints have no guard | Unauthenticated access to application configuration, version information, and Prometheus metrics | T-003, T-004 |
| 3 | Angular SPA stores JWT in `localStorage` with no BFF session layer | XSS anywhere in the app results in full account takeover via token theft | T-012, T-013 |
| 4 | CORS wildcard (`cors()` with no configuration) combined with no CSRF protection | Cross-origin request forgery against any authenticated endpoint; state-changing GET requests (change password uses HTTP GET) | T-015 |
| 5 | Raw SQL string interpolation in authentication and search — no parameterization in the most security-critical data paths | Authentication bypass and full database dump via UNION injection | T-005, T-006 |

#### Overall Architecture Security Rating

🔴 **Critical Gaps** — The application has no functioning security architecture for any of the standard control domains. Private keys are in source code, passwords use MD5, authentication can be bypassed via SQL injection, admin endpoints are unauthenticated, CORS is open, and there is no CSP. This is intentional (it is a training tool), but any production deployment of this codebase would be immediately and trivially compromised.

---

## 3. Security-Relevant Use Cases

### 3.1 Authentication Flow

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant API as Express API
    participant DB as SQLite DB
    participant AUTH as Auth Module

    U->>API: POST /rest/user/login { email, password }
    API->>DB: SELECT * FROM Users WHERE email='${email}' AND password='${md5(password)}'
    Note over DB: RAW SQL - SQL INJECTION POSSIBLE
    DB-->>API: user row or null
    alt user found with TOTP secret
        API-->>U: 401 { status: 'totp_token_required', tmpToken }
        U->>API: POST /rest/2fa/verify { tmpToken, totp }
        API-->>U: 200 { token, bid }
    else user found no TOTP
        API->>AUTH: security.authorize(user) - sign JWT RS256
        Note over AUTH: PRIVATE KEY HARDCODED in source code
        AUTH-->>API: JWT token (6h expiry)
        API-->>U: 200 { authentication: { token, bid, umail } }
        Note over U: localStorage.setItem('token', jwt) - XSS ACCESSIBLE
    else invalid credentials
        API-->>U: 401 Invalid email or password
        Note over API: No rate limiting on /rest/user/login
    end
```

### 3.2 Google OAuth Flow (Deprecated Implicit Flow)

<!-- QA: sequence diagram '3.2 Google OAuth Flow (Deprecated Implicit Flow)' has no alt/else failure path — consider adding error scenarios (e.g., invalid token, network error, permission denied) -->
```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant GOOGLE as Google OAuth IDP
    participant API as Express API
    participant DB as SQLite DB

    U->>GOOGLE: GET /oauth2/auth?response_type=token (IMPLICIT FLOW)
    Note over GOOGLE: Implicit flow - access_token in URL fragment
    Note over GOOGLE: No PKCE, no state parameter, no nonce
    GOOGLE-->>U: redirect /#access_token=TOKEN (token in URL hash)
    Note over U: Token visible in browser history and server logs
    U->>GOOGLE: GET /oauth2/v1/userinfo?access_token=TOKEN
    Note over GOOGLE: Token in query param - leaks to access logs
    GOOGLE-->>U: { email, name, picture }
    U->>API: POST /api/Users { email, password: btoa(email.reverse()) }
    Note over API: Deterministic password derived from email - trivially guessable
    API->>DB: INSERT/check user
    DB-->>API: user record
    U->>API: POST /rest/user/login { email, password: btoa(email.reverse()), oauth: true }
    API-->>U: 200 { token, bid }
    Note over U: localStorage.setItem('token', jwt)
    Note over U: No state validation, no nonce check - CSRF on OAuth callback possible
```

### 3.3 Input Validation and SQL Injection

<!-- QA: sequence diagram '3.3 Input Validation and SQL Injection' has no alt/else failure path — consider adding error scenarios (e.g., invalid token, network error, permission denied) -->
```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant DB as SQLite DB

    A->>API: POST /rest/user/login { email: "' OR 1=1--", password: "anything" }
    Note over API: No input validation on email field
    API->>DB: SELECT * FROM Users WHERE email='' OR 1=1-- AND password='...'
    Note over DB: SQL INJECTION - returns first user (admin)
    DB-->>API: admin user record
    API-->>A: 200 { token: admin_jwt, bid }

    Note over A,DB: Search endpoint also vulnerable
    A->>API: GET /rest/products/search?q='))UNION SELECT * FROM Users--
    Note over API: criteria interpolated directly into SQL
    API->>DB: SELECT * FROM Products WHERE name LIKE '...'))UNION SELECT * FROM Users--...'
    DB-->>API: User table data (emails, MD5 passwords)
    API-->>A: 200 full user table dump
```

### 3.4 File Upload Security

<!-- QA: sequence diagram '3.4 File Upload Security' has no alt/else failure path — consider adding error scenarios (e.g., invalid token, network error, permission denied) -->
```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant FS as File System

    Note over A,FS: XXE Attack via XML upload
    A->>API: POST /file-upload (XML with XXE payload)
    Note over API: libxmljs2.parseXml with noent:true - resolves external entities
    API->>FS: Read /etc/passwd via &xxe; entity
    FS-->>API: file contents
    API-->>A: Error with file contents leaked

    Note over A,FS: Zip Slip / Path Traversal
    A->>API: POST /file-upload (ZIP with ../ftp/legal.md entry)
    Note over API: unzipper.Parse - no canonicalization check before write
    API->>FS: createWriteStream uploads/complaints/../ftp/legal.md
    FS-->>API: file written outside intended directory

    Note over A,FS: B2B RCE via orderLinesData
    A->>API: POST /b2b/v2/orders { orderLinesData: "require('child_process').exec('id')" }
    Note over API: vm.runInContext(safeEval(orderLinesData)) - sandbox escape possible
    API-->>A: code execution result / DoS
```

### 3.5 Authorization and IDOR

<!-- QA: sequence diagram '3.5 Authorization and IDOR' has no alt/else failure path — consider adding error scenarios (e.g., invalid token, network error, permission denied) -->
```mermaid
sequenceDiagram
    participant A as Attacker (User A)
    participant API as Express API
    participant DB as SQLite DB

    A->>API: GET /rest/user/whoami (JWT for User A)
    API-->>A: { id: 5, bid: 5 }

    Note over A,DB: IDOR - access other user's basket
    A->>API: GET /rest/basket/3 (using User A's JWT)
    Note over API: No ownership check - only logs as challenge violation
    API->>DB: SELECT basket WHERE id=3
    DB-->>API: User B's basket
    API-->>A: 200 User B's basket contents

    Note over A,DB: Change password via GET (no current password required)
    A->>API: GET /rest/user/change-password?current=&new=evil&repeat=evil
    Note over API: currentPassword check skipped if falsy - password changed with no auth
    API->>DB: UPDATE Users SET password=md5('evil') WHERE id=A.id
    API-->>A: 200 password changed
```

### 3.6 Secret Management

<!-- QA: sequence diagram '3.6 Secret Management' has no alt/else failure path — consider adding error scenarios (e.g., invalid token, network error, permission denied) -->
```mermaid
sequenceDiagram
    participant DEV as Developer
    participant GIT as Git Repository
    participant ATTACKER as Attacker

    DEV->>GIT: commit lib/insecurity.ts with privateKey hardcoded
    Note over GIT: RSA private key in source history forever

    ATTACKER->>GIT: git clone https://github.com/juice-shop/juice-shop
    GIT-->>ATTACKER: full source including private key
    Note over ATTACKER: Can now forge JWT tokens for any user

    ATTACKER->>ATTACKER: jwt.sign({ data: { id:1, role:'admin', email:'admin@juice-sh.op' } }, privateKey)
    Note over ATTACKER: Valid admin JWT token created
    ATTACKER->>API: GET /api/Users (using forged admin JWT)
    API-->>ATTACKER: 200 all user data
```

### 3.7 SSTI in User Profile

<!-- QA: sequence diagram '3.7 SSTI in User Profile' has no alt/else failure path — consider adding error scenarios (e.g., invalid token, network error, permission denied) -->
```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant PUG as Pug Template Engine

    A->>API: PUT /api/Users/5 { username: "#{7*7}" } (JWT authenticated)
    API->>DB: UPDATE Users SET username='#{7*7}' WHERE id=5
    DB-->>API: user saved

    A->>API: GET /profile (cookie token)
    Note over API: getUserProfile reads username from DB
    API->>PUG: template.replace('_username_', '#{7*7}')
    Note over PUG: username.match(/#{(.*)}/) matches - eval() called!
    PUG->>PUG: eval('7*7') = 49
    API-->>A: userProfile page rendered with evaluated result
    Note over A: Can execute arbitrary Node.js: #{require('child_process').exec('id')}
```

---

## 4. Assets

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|---------------|
| User Credentials (email + password) | Restricted | User account credentials stored in SQLite; passwords MD5-hashed — trivially crackable | T-001, T-005, T-006, T-009 |
| JWT Private Key | Restricted | RSA-2048 private key hardcoded in `lib/insecurity.ts:23` — used to sign all authentication tokens | T-001 |
| Payment Card Data | Restricted | Credit card numbers stored in `Cards` table in SQLite — no field-level encryption | T-005, T-006 |
| User PII (address, email) | Confidential | Shipping addresses, email addresses, profile images | T-005, T-006, T-016 |
| SQLite Database File | Confidential | `data/juiceshop.sqlite` — contains all user, order, payment data | T-005, T-006 |
| Session Tokens (JWT) | Confidential | JWTs stored in `localStorage` — accessible to XSS | T-012, T-013 |
| TOTP Secrets | Confidential | 2FA TOTP secrets stored in `totpSecret` column of Users table | T-005 |
| Application Configuration | Internal | `/rest/admin/application-configuration` — exposed without authentication | T-003 |
| Prometheus Metrics | Internal | `/metrics` endpoint — reveals infrastructure topology, request rates, error rates | T-004 |
| Log Files | Internal | `/support/logs` — directory listing enabled, HTTP access logs publicly browsable | T-017 |
| Source Code / Challenges | Internal | Challenge solution code in `data/static/codefixes/`, snippets exposed via `/snippets/:challenge` | T-018 |
| CTF Signing Key | Confidential | `ctf.key` in repository root — used for CTF challenge verification | T-001 |

---

## 5. Attack Surface

| Entry Point | Protocol/Method | Authentication | Notes | Linked Threats |
|-------------|----------------|----------------|-------|---------------|
| POST /rest/user/login | HTTP POST / JSON | None (login endpoint) | SQL injection; no rate limiting; no account lockout | T-005, T-019 |
| GET /rest/products/search | HTTP GET | None | SQL injection via `q` parameter; returns product and user data | T-006 |
| POST /api/Users | HTTP POST / JSON | None | User registration; no CAPTCHA on main flow | T-020 |
| GET/PUT /api/Users/:id | HTTP GET/PUT | JWT required | IDOR — no ownership verification on GET | T-016 |
| GET /rest/basket/:id | HTTP GET | JWT required | IDOR — any user can read any basket by ID | T-016 |
| GET /rest/user/change-password | HTTP GET | JWT required | Password change via GET query params; no current password needed if empty | T-021 |
| POST /rest/user/reset-password | HTTP POST | None (security Q/A) | Rate-limited; HMAC verification of security answers | T-022 |
| POST /file-upload | HTTP POST / multipart | None | XXE (XML), path traversal (ZIP), type confusion; libxmljs2 with noent:true | T-007, T-008 |
| POST /b2b/v2/orders | HTTP POST / JSON | JWT required | vm.runInContext with user-supplied `orderLinesData` — RCE potential | T-009 |
| POST /profile/image/url | HTTP POST | JWT (cookie) | SSRF — `fetch(url)` with attacker-controlled URL | T-010 |
| GET /profile | HTTP GET | JWT (cookie) | SSTI via `eval()` on username containing `#{...}` pattern | T-011 |
| GET /rest/admin/application-version | HTTP GET | **None** | Exposes version info publicly | T-003 |
| GET /rest/admin/application-configuration | HTTP GET | **None** | Exposes full app configuration including OAuth client ID | T-003 |
| GET /metrics | HTTP GET | **None** | Prometheus metrics — infrastructure topology, error rates | T-004 |
| GET /api-docs | HTTP GET | **None** | Swagger UI for B2B API — full API surface disclosure | T-003 |
| GET /support/logs | HTTP GET | **None** | Directory listing of HTTP access logs | T-017 |
| GET /encryptionkeys | HTTP GET | **None** | Directory listing of JWT public key and premium key | T-001 |
| GET /ftp | HTTP GET | **None** | Directory listing of FTP files including confidential documents | T-018 |
| GET /redirect?to= | HTTP GET | None | Open redirect; allowlist uses `includes()` — bypassable | T-023 |
| POST /rest/chatbot/respond | HTTP POST | JWT | Chatbot NLP interface | T-024 |
| POST /rest/web3/walletNFTVerify | HTTP POST | None | Blockchain wallet interaction | T-025 |
| WebSocket (socket.io) | WS | None | Server-side challenge verification events | T-025 |
| POST /rest/memories | HTTP POST / multipart | JWT | Image upload to disk; file type by extension only | T-008 |
| GET /rest/user/authentication-details | HTTP GET | JWT required | Lists all authenticated user tokens (tokenMap) | T-017 |
| DELETE /api/Users/:id | HTTP DELETE | JWT required | Soft delete; no admin check — any user can delete any user | T-016 |
| PATCH /rest/products/reviews | HTTP PATCH | JWT required | NoSQL-style update — potential NoSQL injection | T-026 |
| GET /dataerasure | HTTP GET | None (form) | GDPR data erasure form — CSRF possible | T-015 |
| GET /rest/captcha | HTTP GET | None | Returns captcha challenge — replay attack vector | T-022 |

**Route Audit Findings:**

- `/rest/admin/application-version` and `/rest/admin/application-configuration` — **Critical: No authentication** (server.ts:604-605)
- `/metrics` — **Critical: No authentication**, exposes Prometheus metrics (server.ts:718)
- `/api-docs` (Swagger UI) — **High: No authentication**, exposes full B2B API surface
- `/support/logs` — **High: No authentication**, directory listing of HTTP access logs
- `/encryptionkeys` — **High: No authentication**, directory listing of cryptographic keys
- `/ftp` — **High: No authentication**, directory listing with serve-index

---

## 6. Trust Boundaries

The system has a critically weak trust model. No component enforces fail-closed behavior by default. Missing authentication checks default to public access.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|-------------|---------------|
| TB-1 | Public Internet to Express App | Any HTTP client | Express route handlers | No mechanism (no WAF, no reverse proxy, no TLS termination) | All traffic reaches application directly; no filtering layer | T-001 through T-026 |
| TB-2 | Unauthenticated to Authenticated | Anonymous user | Protected REST routes | express-jwt 0.1.3 middleware on select routes only | Wildcard CORS, inconsistent middleware application, obsolete library | T-003, T-004, T-015, T-016 |
| TB-3 | Customer to Admin/Accounting | Authenticated customer | Admin/accounting routes | `security.isAccounting()` role check on some routes; no check on `/rest/admin/*` | `/rest/admin/*` endpoints have NO auth at all; role escalation via SQL injection | T-003, T-005 |
| TB-4 | Application to Data Tier | Express route handlers | SQLite / MarsDB | Sequelize ORM (partially bypassed by raw SQL) | Raw SQL string interpolation in login and search; SQLite file unencrypted | T-005, T-006 |

**Boundary TB-2 notes:** The `security.isAuthorized()` middleware is applied correctly to basket, feedback, B2B, and privacy routes. However, it is absent from the following endpoints that handle sensitive data: `/rest/admin/application-version`, `/rest/admin/application-configuration`, `/metrics`, `/api-docs`, `/support/logs`, `/encryptionkeys`, `/ftp`. The change-password endpoint uses HTTP GET, making CSRF trivial even with same-origin restrictions.

**Boundary TB-3 notes:** The IP filter on `/api/Quantitys/:id` uses the value `'123.456.789'` — this is not a valid IP address and the filter effectively blocks all traffic, creating an unintended denial-of-service for the accounting feature rather than restricting access.

---

## 7. Identified Security Controls

**Critical Gaps Summary:** The five most critical gaps are: (1) No rate limiting on the login endpoint enabling unlimited brute-force; (2) No CSP header enabling stored XSS to steal JWT tokens from localStorage; (3) Hardcoded JWT private key enabling token forgery; (4) MD5 password hashing enabling offline cracking of all user passwords; (5) No CSRF protection combined with a state-changing GET endpoint (change password).

**Legend:** ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness |
|--------|---------|---------------|---------------|
| **Identity & Access Management** | JWT token issuance and validation | [lib/insecurity.ts:54-56](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) — `expressJwt()` + `jwt.sign()` with RS256 | 🔶 Weak — express-jwt 0.1.3 (extremely outdated, ~2013), jsonwebtoken 0.4.0; private key hardcoded in source |
| **Identity & Access Management** | Password hashing | [lib/insecurity.ts:46](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:46) — `crypto.createHash('md5')` | ❌ Missing — MD5 is not a password hashing function; no salt, trivially crackable |
| **Identity & Access Management** | Two-Factor Authentication (TOTP) | [routes/2fa.ts](vscode://file/home/mrohr/juice-shop/routes/2fa.ts), [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) — otplib | ⚠️ Partial — TOTP available but optional; not enforced for admin accounts |
| **Identity & Access Management** | Account lockout / brute-force protection | None found on `/rest/user/login` | ❌ Missing — No lockout, no rate limiting on login endpoint |
| **Authorization** | Role-based access control | [lib/insecurity.ts:156-164](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:156) — `isAccounting()` role check | ⚠️ Partial — Role check present on accounting routes; absent on `/rest/admin/*`, `/metrics` |
| **Authorization** | Resource ownership verification | No ownership check in [routes/basket.ts:22](vscode://file/home/mrohr/juice-shop/routes/basket.ts:22) | ❌ Missing — Basket endpoint returns any basket by ID without verifying ownership |
| **Data Protection** | TLS encryption in transit | Not configured in application | ❌ Missing — TLS must be terminated by infrastructure; no HSTS header set |
| **Data Protection** | Database encryption at rest | SQLite file stored unencrypted at `data/juiceshop.sqlite` | ❌ Missing — No field-level or disk-level encryption |
| **Secret Management** | Secrets in environment variables | [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) — private key hardcoded | ❌ Missing — RSA private key, HMAC secret, cookie secret all hardcoded in source |
| **Frontend Security** | Content Security Policy | Helmet configured but CSP commented out: `// app.use(helmet.xssFilter())` | ❌ Missing — No CSP header; comment in server.ts explicitly disables XSS filter |
| **Frontend Security** | Output encoding | [frontend/src/app/about/about.component.ts:119](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119) — `bypassSecurityTrustHtml()` used in 8+ places | 🔶 Weak — Angular XSS protection deliberately bypassed in multiple components |
| **Frontend Security** | CSRF protection | No CSRF middleware found | ❌ Missing — No SameSite cookie attribute, no CSRF tokens; change-password uses GET |
| **Output Encoding** | Parameterized queries | Sequelize used for most queries; raw SQL in [routes/login.ts:44](vscode://file/home/mrohr/juice-shop/routes/login.ts:44) and [routes/search.ts:24](vscode://file/home/mrohr/juice-shop/routes/search.ts:24) | 🔶 Weak — ORM used generally but bypassed for most security-critical queries |
| **Audit & Logging** | Security event logging | [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) — Winston console transport; Morgan HTTP access logs | 🔶 Weak — No structured security events (login, auth failure, privilege escalation); console-only transport; access logs publicly browsable |
| **Infrastructure & Network** | CORS policy | [server.ts:181-182](vscode://file/home/mrohr/juice-shop/server.ts:181) — `app.use(cors())` with no config | ❌ Missing — Wildcard CORS (`*`); comment: "Bludgeon solution for possible CORS problems: Allow everything!" |
| **Infrastructure & Network** | Security headers (partial) | [server.ts:185-188](vscode://file/home/mrohr/juice-shop/server.ts:185) — Helmet noSniff + frameguard; `x-powered-by` disabled | ⚠️ Partial — Some headers present (noSniff, frameguard) but no CSP, no HSTS, no Referrer-Policy |
| **Infrastructure & Network** | Non-root container | [Dockerfile:35](vscode://file/home/mrohr/juice-shop/Dockerfile:35) — `USER 65532` in distroless image | ✅ Adequate — Container runs as non-root UID 65532 |
| **Dependency & Supply Chain** | Lock files | No `package-lock.json` found at repository root | ❌ Missing — No dependency integrity verification; supply chain attack possible |
| **Dependency & Supply Chain** | SBOM generation | [Dockerfile:22](vscode://file/home/mrohr/juice-shop/Dockerfile:22) — `npm run sbom` via CycloneDX during Docker build | ✅ Adequate — SBOM generated at build time |
| **Security Testing & Pipeline** | SAST | [.github/workflows/codeql-analysis.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml) — CodeQL with `security-extended` | ✅ Adequate — CodeQL runs on every push/PR |
| **OAuth/OIDC Implementation** | PKCE enforcement | Not present — implicit flow used; no `code_verifier` | ❌ Missing — Implicit flow (`response_type=token`) used; deprecated per RFC 9700 |
| **OAuth/OIDC Implementation** | State parameter validation | No `state` parameter in OAuth flow | ❌ Missing — CSRF on OAuth callback possible |
| **OAuth/OIDC Implementation** | Token not in URL | [frontend/src/app/app.routing.ts:262](vscode://file/home/mrohr/juice-shop/frontend/src/app/app.routing.ts:262) — `#access_token=` in URL hash | ❌ Missing — Access token exposed in URL fragment; leaks to browser history |
| **SPA Architecture** | BFF session layer | No BFF found | ❌ Missing — SPA calls API directly; tokens in localStorage |
| **SPA Architecture** | Tokens not in localStorage | [frontend/src/app/oauth/oauth.component.ts:53](vscode://file/home/mrohr/juice-shop/frontend/src/app/oauth/oauth.component.ts:53) — `localStorage.setItem('token', ...)` | ❌ Missing — JWT tokens stored in localStorage, accessible to any XSS |

---

### 7b. Requirements Compliance

> Requirements source: remote · 38 requirements checked · Generated: 2026-04-08T21:35:00Z

| Status | ID | Priority | Requirement | Evidence | Finding |
|--------|----|----------|-------------|----------|---------|
| ❌ | [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | `MUST` | Anti-CSRF protection | [server.ts:595](vscode://file/home/mrohr/juice-shop/server.ts:595) | GET /rest/user/change-password is state-changing; no SameSite cookie; no CSRF tokens |
| ❌ | [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) | `MUST` | No sensitive data in client-side storage | [oauth.component.ts:53](vscode://file/home/mrohr/juice-shop/frontend/src/app/oauth/oauth.component.ts:53) | JWT auth token stored in localStorage |
| ❌ | [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | `MUST` | Restrictive CORS | [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) | CORS wildcard: `app.use(cors())` — comment says "Allow everything!" |
| ❌ | [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | `SHOULD` | Content-Security-Policy header | [server.ts:187](vscode://file/home/mrohr/juice-shop/server.ts:187) | CSP explicitly disabled: `// app.use(helmet.xssFilter())` |
| ❌ | [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | `MUST` | HSTS header | server.ts | No HSTS header configured anywhere |
| ✅ | [WEB-006](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html) | `MUST` | Mature frontend framework | [frontend/package.json](vscode://file/home/mrohr/juice-shop/frontend/package.json) | Angular 20 is a mature, actively maintained framework |
| ❌ | [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | `MUST` | Encode user-controlled output | [search-result.component.ts:132](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132) | `bypassSecurityTrustHtml()` used in 8+ components |
| ❌ | [WEB-008](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | `SHOULD` | Referrer-Policy and Permissions-Policy | server.ts | Referrer-Policy absent; featurePolicy present but limited |
| ❌ | [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | `MUST` | No internal details in error responses | [server.ts:676](vscode://file/home/mrohr/juice-shop/server.ts:676) | `errorhandler()` middleware in use — exposes stack traces to clients |
| ❌ | [EH-002](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | `MUST` | Generic error messages to clients | [server.ts:676](vscode://file/home/mrohr/juice-shop/server.ts:676) | errorhandler sends full error details to client |
| ⚠️ | [EH-003](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | `MUST` | Consistent auth failure responses | [routes/login.ts:58](vscode://file/home/mrohr/juice-shop/routes/login.ts:58) | Login returns "Invalid email or password" — generic; but timing differences possible |
| ❌ | [HN-001](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | `MUST` | Disable tech-disclosure headers | [server.ts:188](vscode://file/home/mrohr/juice-shop/server.ts:188) | `x-powered-by` disabled; `Server` header not addressed; version number shown in UI |
| ❌ | [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | `MUST` | Debug/management endpoints not public | [server.ts:604-605,718](vscode://file/home/mrohr/juice-shop/server.ts:604) | /rest/admin/* and /metrics have no auth |
| ❌ | [HN-003](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | `MUST` | Disable unused features/defaults | [server.ts:286](vscode://file/home/mrohr/juice-shop/server.ts:286) | Swagger UI, FTP listing, log listing, key listing all enabled |
| ❌ | [HN-004](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | `SHOULD` | WAF in front of application | Dockerfile, no reverse proxy config | No WAF configured |
| ❌ | [AC-001](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | `MUST` | Mutual auth for API-to-API | B2B API uses one-way JWT only | No mTLS or client credential flow for B2B |
| ❌ | [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | `MUST` | RBAC / deny by default | [server.ts:604-605](vscode://file/home/mrohr/juice-shop/server.ts:604) | Admin endpoints accessible without any authentication |
| ❌ | [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | `MUST` | Rate limiting on all external endpoints | [server.ts:343](vscode://file/home/mrohr/juice-shop/server.ts:343) | Rate limiting only on reset-password and 2FA; not on login |
| ❌ | [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | `MUST` | MFA via central IdP | [config/default.yml:75](vscode://file/home/mrohr/juice-shop/config/default.yml:75) | Internal auth with optional TOTP; not via central IdP; no mandatory MFA |
| ❌ | [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) | `MUST` | Validate OAuth token claims | [lib/insecurity.ts:54](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) | No `iss`/`aud` claim validation; only signature checked |
| ❌ | [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | `MUST` | Resource-level authorization (IDOR prevention) | [routes/basket.ts:22](vscode://file/home/mrohr/juice-shop/routes/basket.ts:22) | No ownership check; any authenticated user can access any basket |
| ❌ | [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | `MUST` | Allowlist input validation | [routes/login.ts:44](vscode://file/home/mrohr/juice-shop/routes/login.ts:44) | No input validation on email/password fields before SQL query |
| ❌ | [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | `MUST` | Harden XML parsers against XXE | [routes/fileUpload.ts:83](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83) | `libxml.parseXml` with `noent: true` — external entities enabled |
| ❌ | [IV-003](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) | `MUST` | Restrict deserialization | [routes/b2bOrder.ts:24](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:24) | `vm.runInContext(safeEval(orderLinesData))` with user-supplied data |
| ❌ | [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | `MUST` | Parameterized queries | [routes/login.ts:44](vscode://file/home/mrohr/juice-shop/routes/login.ts:44) | Raw SQL string interpolation in login and search |
| ❌ | [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | `MUST` | Validate and securely store uploads | [routes/fileUpload.ts:35-43](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:35) | Extension-only validation; ZIP path traversal; no MIME type check |
| ❌ | [IV-006](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | `MUST` | Payload size and field limits | [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) | No enforced size limits on most endpoints |
| ❌ | [DP-001](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | `MUST` | Encrypt data at rest | SQLite file at `data/juiceshop.sqlite` | No database encryption |
| ❌ | [DP-002](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | `MUST` | CSPRNG for tokens/keys | [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) | Static hardcoded key; `deluxeToken` generation needs review |
| ❌ | ⚠️ [DP-003](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | `MUST` | Sensitive data in POST body not URL | [server.ts:595](vscode://file/home/mrohr/juice-shop/server.ts:595) | change-password uses GET with password in query params |
| ❌ | [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | `MUST` | Do not store passwords; delegate to IdP | [models/user.ts:57](vscode://file/home/mrohr/juice-shop/models/user.ts:57) | Passwords stored locally as MD5 hashes |
| ❌ | [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | `MUST` | Secrets in dedicated secret manager | [lib/insecurity.ts:23,47](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) | Private key, HMAC secret, cookie secret all hardcoded |
| ❌ | [DP-006](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | `MUST` | TLS 1.2+ for all external data | No TLS config in application | No TLS in app; depends on infrastructure |
| ❌ | [SC-001](https://owasp.org/www-project-dependency-check/) | `MUST` | SCA in CI/CD | .github/workflows/ci.yml | No SCA tool (Snyk, Trivy, Dependabot) in CI |
| ❌ | [SC-002](https://owasp.org/www-project-dependency-check/) | `MUST` | Pinned dependencies with lockfile | No package-lock.json at repo root | No lockfile; floating `^` versions in package.json |
| ✅ | [SC-004](https://owasp.org/www-project-cyclonedx/) | `SHOULD` | SBOM for each release | [Dockerfile:22](vscode://file/home/mrohr/juice-shop/Dockerfile:22) | CycloneDX SBOM generated during Docker build |
| ✅ | [SC-006](https://owasp.org/www-community/controls/Static_Code_Analysis) | `MUST` | SAST in CI/CD | [.github/workflows/codeql-analysis.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml) | CodeQL with security-extended runs on every push |
| ❌ | [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | `MUST` | Log security events | [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) | No structured security event logging (auth success/failure, privilege escalation) |
| ❌ | [LM-002](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | `MUST` | Structured log format | [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) | Winston uses `simple()` format, not JSON/structured |
| ❌ | [LM-003](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | `MUST` | Centralized tamper-resistant log aggregation | [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) | Console-only transport; no centralized log aggregation |
| ❌ | [LM-006](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html) | `MUST` | No sensitive values in logs | [server.ts:338](vscode://file/home/mrohr/juice-shop/server.ts:338) | Morgan combined format logs full URLs — passwords in query strings (change-password GET) logged |
| ❌ | [IF-001](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | `MUST` | Container image scanning in CI | .github/workflows/ | No image scanning (Trivy, Grype, etc.) in CI |
| ✅ | [IF-002](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | `MUST` | Non-root container | [Dockerfile:35](vscode://file/home/mrohr/juice-shop/Dockerfile:35) | USER 65532 in distroless image |
| ❌ | [IF-007](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | `SHOULD` | Pin base images to SHA256 | [Dockerfile:1](vscode://file/home/mrohr/juice-shop/Dockerfile:1) | `FROM node:24` — mutable tag, not SHA-pinned |

**Summary:** 4 ✅ PASS · 1 ⚠️ PARTIAL · 33 ❌ FAIL · 0 ❓ UNVERIFIABLE (38 total)

#### ❌ [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) — Anti-CSRF Protection

**Attack:** An attacker can host a malicious webpage that issues a GET request to `/rest/user/change-password?current=&new=evil123&repeat=evil123`. Any authenticated Juice Shop user visiting the malicious page will have their password silently changed.
**Evidence:** [server.ts:595](vscode://file/home/mrohr/juice-shop/server.ts:595) — `app.get('/rest/user/change-password', ...)` — state-changing operation on GET
**Effort:** M
**Fix:**
- Before: `app.get('/rest/user/change-password', changePassword())`
- After: Change to `app.post('/rest/user/change-password', ...)` with CSRF token middleware (e.g., `csurf` or `csrf-csrf` library)

#### ❌ [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — Token Not in localStorage

**Attack:** Any stored XSS vulnerability (which exists in multiple Angular components via `bypassSecurityTrustHtml`) allows an attacker to exfiltrate the JWT from `localStorage.getItem('token')`, gaining permanent account access.
**Evidence:** [oauth.component.ts:53](vscode://file/home/mrohr/juice-shop/frontend/src/app/oauth/oauth.component.ts:53), [request.interceptor.ts:13](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13)
**Effort:** H
**Fix:** Implement a BFF (Backend for Frontend) pattern: store JWT in an `HttpOnly; Secure; SameSite=Strict` cookie managed by the server. The SPA receives no token and cannot be XSS'd for it.

#### ❌ [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized Queries

**Attack:** SQL injection in the login endpoint allows authentication bypass (log in as any user including admin) and in the search endpoint allows UNION-based extraction of the entire Users table including emails and MD5-hashed passwords.
**Evidence:** [routes/login.ts:44](vscode://file/home/mrohr/juice-shop/routes/login.ts:44), [routes/search.ts:24](vscode://file/home/mrohr/juice-shop/routes/search.ts:24)
**Effort:** S
**Fix:**
- Before: `` models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true }) ``
- After: `models.sequelize.query('SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL', { bind: [req.body.email, security.hash(req.body.password)], model: UserModel, plain: true })`

#### ❌ [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets in Secret Manager

**Attack:** The RSA private key used to sign all JWT tokens is hardcoded in `lib/insecurity.ts:23` and committed to the public GitHub repository. Any attacker can clone the repo, extract the private key, and forge admin tokens without compromising the server.
**Evidence:** [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23)
**Effort:** M
**Fix:**
- Before: `const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIIC...'`
- After: `const privateKey = process.env.JWT_PRIVATE_KEY || fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE || '/run/secrets/jwt-private-key', 'utf8')`
  Store the key in a secret manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secret with RBAC).

---

## 8. Threat Register

**Risk Distribution:** Critical: 6 · High: 10 · Medium: 8 · Low: 2 · **Total: 26**
**STRIDE Coverage:** Spoofing: 5 · Tampering: 6 · Repudiation: 2 · Information Disclosure: 7 · Denial of Service: 3 · Elevation of Privilege: 3

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|------------------|-------------|
| <a id="t-001"></a>T-001 | Auth Subsystem | Spoofing | The RSA private key used to sign all JWT tokens is hardcoded in `lib/insecurity.ts:23` and available in the public GitHub repository. An attacker clones the repo, extracts the private key, and calls `jwt.sign({ data: { id:1, role:'admin', email:'admin@juice-sh.op' } }, privateKey, { algorithm: 'RS256' })` to forge a valid admin JWT token, gaining full administrative access to all API endpoints without any credentials. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT signature validates with public key. Tokens expire after 6h. | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | Auth Subsystem | Spoofing | Google OAuth uses the deprecated implicit flow (`response_type=token`). The `access_token` appears in the URL hash (`#access_token=...`) and is not validated with a `state` parameter, making it susceptible to CSRF attacks on the OAuth callback. The derived password (`btoa(email.reverse())`) is deterministic and trivially guessable from the email address. Attacker can auto-register or take over any Google-linked account. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Tokens validated server-side | [M-002](#m-002) |
| <a id="t-003"></a>T-003 | Admin Interface | Information Disclosure | `/rest/admin/application-version` and `/rest/admin/application-configuration` endpoints have no authentication middleware (server.ts:604-605). Any unauthenticated request receives full application configuration including Google OAuth client ID, authorized redirect URIs, feature flags, and the application name. This reveals reconnaissance information for further targeted attacks. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-003](#m-003) |
| <a id="t-004"></a>T-004 | Express Backend | Information Disclosure | The Prometheus `/metrics` endpoint (server.ts:718) is exposed without authentication. It reveals HTTP request counts, file upload counts/errors, error rates by status code, and internal application metrics. This allows infrastructure mapping, traffic pattern analysis, and targeted attack timing based on when the application is under load or experiencing errors. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-003](#m-003) |
| <a id="t-005"></a>T-005 | Auth Subsystem | Tampering | SQL injection in `routes/login.ts:44`: the email and password fields are directly interpolated into a raw SQL query. An attacker submits `email = "' OR 1=1--"` to bypass authentication entirely and receive a JWT token for the first user in the database (typically admin). Full authentication bypass with no credentials required. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | MD5 hash applied to password before query | [M-004](#m-004) |
| <a id="t-006"></a>T-006 | Express Backend | Information Disclosure | SQL injection in `routes/search.ts:24`: the `q` parameter is directly interpolated into a raw SQL query. An attacker submits `'))UNION SELECT id,email,password,role,deluxeToken,lastLoginIp,profileImage,totpSecret,isActive,createdAt,updatedAt,deletedAt FROM Users--` to dump the entire Users table including emails, MD5-hashed passwords, TOTP secrets, and role information. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — query result is returned to client | [M-004](#m-004) |
| <a id="t-007"></a>T-007 | File Upload Handler | Information Disclosure | XXE in `routes/fileUpload.ts:83`: `libxml.parseXml()` is called with `noent: true` (external entity resolution enabled). An attacker uploads an XML file containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to read arbitrary files from the server filesystem, potentially including the SQLite database file or environment variables. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Sandboxed in vm.createContext | [M-005](#m-005) |
| <a id="t-008"></a>T-008 | File Upload Handler | Tampering | Path traversal via ZIP upload in `routes/fileUpload.ts:42`: the unzipper library extracts files using client-provided paths. Although there is a check for `path.resolve('.')`, the path is not properly canonicalized before the write. An attacker crafts a ZIP with an entry named `../ftp/legal.md` to overwrite files outside the `uploads/complaints/` directory, potentially replacing application files. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | `absolutePath.includes(path.resolve('.'))` — partial check | [M-005](#m-005) |
| <a id="t-009"></a>T-009 | B2B API | Elevation of Privilege | RCE potential in `routes/b2bOrder.ts:24`: user-supplied `orderLinesData` is executed via `vm.runInContext('safeEval(orderLinesData)', sandbox)`. While `notevil` attempts to sandbox execution, Node.js `vm` module is not a security boundary. An attacker with JWT authentication can supply code to escape the sandbox and execute arbitrary commands on the server. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT required; notevil sandbox; vm.runInContext timeout | [M-006](#m-006) |
| <a id="t-010"></a>T-010 | Express Backend | Information Disclosure | SSRF in `routes/profileImageUrlUpload.ts:26`: `fetch(url)` is called with an attacker-controlled URL without any validation. An authenticated attacker can probe internal services (`http://169.254.169.254/latest/meta-data/` for AWS metadata, `http://localhost:3000/rest/admin/application-configuration`), scan internal ports, or exfiltrate data from services accessible within the container network. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT cookie required | [M-007](#m-007) |
| <a id="t-011"></a>T-011 | Express Backend | Elevation of Privilege | SSTI/eval in `routes/userProfile.ts:63`: username values matching `#{...}` pattern are passed directly to `eval()`. An authenticated attacker sets their username to `#{require('child_process').execSync('id').toString()}` and visits `/profile` to execute arbitrary Node.js code on the server, achieving full remote code execution with the process owner's privileges (UID 65532). | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT authentication required; only triggered if challenge is enabled | [M-006](#m-006) |
| <a id="t-012"></a>T-012 | Angular Frontend | Information Disclosure | JWT tokens are stored in `localStorage` (accessible to any JavaScript on the page) rather than `HttpOnly` cookies. The application has multiple instances of `bypassSecurityTrustHtml()` in Angular components. Any stored XSS vulnerability allows `localStorage.getItem('token')` to exfiltrate the JWT, giving the attacker persistent access to the victim's account until token expiry (6 hours). | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-008](#m-008) |
| <a id="t-013"></a>T-013 | Angular Frontend | Tampering | Multiple Angular components call `this.sanitizer.bypassSecurityTrustHtml()` with user-controlled data (product descriptions in `search-result.component.ts:132`, last login IP in `last-login-ip.component.ts:39`, user emails in `administration.component.ts:60`). This disables Angular's built-in XSS protection, enabling stored XSS attacks against all users who view affected pages. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-008](#m-008), [M-009](#m-009) |
| <a id="t-014"></a>T-014 | Auth Subsystem | Information Disclosure | MD5 is used for all password storage (`lib/insecurity.ts:46`). MD5 is not a password hashing function — it has no salt, no work factor, and runs at billions of hashes per second on GPU hardware. Once the Users table is extracted via SQL injection (T-006), all passwords are immediately crackable using rainbow tables or brute force. Pre-seeded admin password `admin123` is trivially in every dictionary. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — MD5 with no salt | [M-010](#m-010) |
| <a id="t-015"></a>T-015 | Express Backend | Tampering | CSRF attack on password change: `GET /rest/user/change-password?current=&new=evil&repeat=evil` is a state-changing operation served on an HTTP GET endpoint. Combined with wildcard CORS (`app.use(cors())`), any malicious website can embed `<img src="http://target:3000/rest/user/change-password?new=evil&repeat=evil">` to change the password of any visiting authenticated user. No CSRF token is required; omitting `current` skips the current-password check. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT token required | [M-011](#m-011) |
| <a id="t-016"></a>T-016 | Express Backend | Elevation of Privilege | IDOR in basket access: `GET /rest/basket/:id` accepts any numeric basket ID without verifying that the requesting user owns that basket. The challenge detection code in `routes/basket.ts:22` only logs the violation as a solved challenge — it does not block the request. Any authenticated user can enumerate and read other users' basket contents, exposing product selections and purchase history. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT required | [M-012](#m-012) |
| <a id="t-017"></a>T-017 | Express Backend | Information Disclosure | HTTP access logs are browsable at `/support/logs` without authentication (server.ts:281-283). The Morgan `combined` format includes full request URLs. Since `GET /rest/user/change-password?new=...` is a valid endpoint, the new password value appears in plaintext in the access logs, which are publicly browsable. This leaks all recently changed passwords to any unauthenticated visitor. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-003](#m-003) |
| <a id="t-018"></a>T-018 | Express Backend | Information Disclosure | Directory listing is enabled for `/ftp` (serve-index, server.ts:269), `/encryptionkeys` (server.ts:277), and `/.well-known` (server.ts:273). The `/encryptionkeys` directory contains `jwt.pub` (JWT public key) and `premium.key`. The `/ftp` directory contains documents including `legal.md`. An unauthenticated attacker can enumerate and download all files. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-003](#m-003) |
| <a id="t-019"></a>T-019 | Auth Subsystem | Denial of Service | No rate limiting on `POST /rest/user/login`. An attacker can perform unlimited login attempts to brute-force user passwords. Given that passwords are MD5-hashed (T-014), and common passwords like `admin123` are in use, this makes offline dictionary attacks against the MD5 hashes even faster. Online brute-force of the login endpoint itself is also feasible for targeted accounts. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-013](#m-013) |
| <a id="t-020"></a>T-020 | Express Backend | Denial of Service | No server-side payload size limits enforced on most endpoints beyond file upload. An attacker can send arbitrarily large JSON bodies to API endpoints, potentially exhausting memory. The YAML file upload handler (`handleYamlUpload`) processes user-supplied YAML without size limits, enabling YAML bomb attacks that exhaust parser memory. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | `checkUploadSize` (challenge detector, not hard limit) | [M-014](#m-014) |
| <a id="t-021"></a>T-021 | Auth Subsystem | Spoofing | Password change accepts a missing `current` password field: `routes/changePassword.ts:38` — `if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password)` — if `currentPassword` is falsy (empty string, undefined), the check is skipped. An attacker with a valid JWT (stolen via XSS, T-012) or via CSRF (T-015) can change the user's password without knowing the current password, making account takeover permanent. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT required | [M-011](#m-011) |
| <a id="t-022"></a>T-022 | Auth Subsystem | Repudiation | No security event logging: Winston is configured with only a console transport (`lib/logger.ts`) and simple format. No structured security events are logged for authentication success/failure, role escalation, or privilege operations. An attacker can perform SQL injection, account takeover, and data exfiltration with no audit trail in any persistent log store. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Morgan HTTP access logs (console + file) | [M-015](#m-015) |
| <a id="t-023"></a>T-023 | Express Backend | Spoofing | Open redirect in `routes/redirect.ts:15`: `security.isRedirectAllowed(toUrl)` uses `url.includes(allowedUrl)` for the allowlist check. An attacker can bypass the allowlist with a URL like `https://evil.com/https://github.com/juice-shop/juice-shop` — this contains an allowed URL as a substring while redirecting to an evil domain. Used for phishing (send victims a "trusted" Juice Shop link that redirects to malware). | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Allowlist present but bypassable | [M-016](#m-016) |
| <a id="t-024"></a>T-024 | Express Backend | Information Disclosure | Stack traces exposed to clients: the `errorhandler()` middleware (server.ts:676) is the Express development error handler that sends full error details including stack traces to HTTP clients. Any unhandled error reveals file paths, function names, and internal application structure, aiding further reconnaissance. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-017](#m-017) |
| <a id="t-025"></a>T-025 | Express Backend | Repudiation | No lock file (`package-lock.json`) exists for the server-side dependencies. The `package.json` uses caret (`^`) ranges for most dependencies. Without a lock file, a CI build or `npm install` may pull different (potentially malicious) versions of dependencies, enabling a supply chain attack without any evidence trail in the repository. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | CycloneDX SBOM in Docker build | [M-018](#m-018) |
| <a id="t-026"></a>T-026 | Express Backend | Denial of Service | YAML file upload (`handleYamlUpload`) in `routes/fileUpload.ts` uses `js-yaml` v3.14.0 to parse user-supplied YAML without size limits. YAML bombs (deeply nested anchors/aliases) can cause exponential memory and CPU consumption. Combined with no rate limiting on the file upload endpoint, this creates a denial-of-service vector. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-014](#m-014) |

---

## 9. Critical Findings

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-001 — Hardcoded JWT Private Key in Source Code

**Scenario:** The RSA-2048 private key used to sign all JWTs is hardcoded at `lib/insecurity.ts:23` and pushed to the public GitHub repository. Any person who has read access to the source code can forge valid JWT tokens for any user (including admin) without knowing any credentials.
**Current state:** Private key embedded as a string literal in `lib/insecurity.ts:23`. The corresponding public key is also accessible via the unauthenticated `/encryptionkeys` directory listing.
→ **Mitigation:** [M-001 — Move JWT private key to environment variable or secret manager](#m-001)

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-005 — SQL Injection in Login Endpoint (Authentication Bypass)

**Scenario:** The login query at `routes/login.ts:44` interpolates `req.body.email` and `security.hash(req.body.password)` directly into a raw SQL string. Submitting `email = "' OR 1=1--"` bypasses authentication entirely, returning the first database user (admin).
**Current state:** No input validation, no parameterization, no rate limiting on the endpoint.
→ **Mitigation:** [M-004 — Replace raw SQL with parameterized queries](#m-004)

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-006 — SQL Injection in Product Search (Full DB Dump)

**Scenario:** `routes/search.ts:24` — the `q` parameter is interpolated into SQL. UNION injection extracts the complete Users table including emails and MD5-hashed passwords, payment card data, and TOTP secrets.
**Current state:** No input sanitization. The returned JSON includes arbitrary query results. [routes/search.ts:24](vscode://file/home/mrohr/juice-shop/routes/search.ts:24)
→ **Mitigation:** [M-004 — Replace raw SQL with parameterized queries](#m-004)

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-014 — MD5 Password Hashing (Trivially Crackable)

**Scenario:** All user passwords are hashed with unsalted MD5 (`crypto.createHash('md5')`). Once extracted via SQL injection, the complete user credential database can be cracked in minutes using GPU-accelerated tools (Hashcat/John). The admin password `admin123` is in every major dictionary.
**Current state:** `lib/insecurity.ts:46` — `crypto.createHash('md5').update(data).digest('hex')`. No salt, no work factor.
→ **Mitigation:** [M-010 — Replace MD5 with bcrypt/Argon2 password hashing](#m-010)

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-012 — JWT Tokens in localStorage (XSS Token Theft)

**Scenario:** JWT tokens are stored in `localStorage` (`oauth.component.ts:53`, `request.interceptor.ts:13`). The application has 8+ instances of `bypassSecurityTrustHtml()` that disable Angular's XSS protection. Any stored XSS payload exfiltrates `localStorage.getItem('token')` for full account takeover.
**Current state:** No `HttpOnly` cookies, no BFF session layer. Token directly accessible to JavaScript.
→ **Mitigation:** [M-008 — Implement HttpOnly cookie for JWT token storage](#m-008)

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-013 — Stored XSS via bypassSecurityTrustHtml in 8+ Components

**Scenario:** Angular's `DomSanitizer.bypassSecurityTrustHtml()` is called with user-controlled data in product descriptions, user emails, and last-login IP. Any user who can inject HTML markup (e.g., via product review or user registration) will have it executed in the browsers of all users who view the affected page.
**Current state:** [search-result.component.ts:132](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132), [administration.component.ts:78](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:78), and 6 other locations.
→ **Mitigation:** [M-009 — Remove bypassSecurityTrustHtml; use data binding](#m-009)

---


### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-002 — Deprecated Google OAuth Implicit Flow with CSRF and Deterministic Password

**Scenario:** Google OAuth uses the deprecated implicit flow (`response_type=token`). The `access_token` appears in the URL hash (`#access_token=...`) and is not validated with a `state` parameter, making it susceptible to CSRF attacks on the OAuth callback. The derived password (`btoa(email.reverse())`) is deterministic and trivially guessable from the email address.

**Current state:** Implicit flow in use; no PKCE, no state parameter, no nonce validation. Password derivation is deterministic.

→ **Mitigation:** [M-002 — Replace Implicit OAuth Flow with Authorization Code + PKCE](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-003 — Unauthenticated Admin Configuration Endpoints

**Scenario:** `/rest/admin/application-version` and `/rest/admin/application-configuration` endpoints have no authentication middleware (server.ts:604-605). Any unauthenticated request receives full application configuration including Google OAuth client ID, authorized redirect URIs, feature flags, and the application name.

**Current state:** No authentication on `/rest/admin/*` endpoints. Any internet client can retrieve full application configuration.

→ **Mitigation:** [M-003 — Add Authentication to Admin, Metrics, and Directory Endpoints](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-004 — Unauthenticated Prometheus Metrics Endpoint

**Scenario:** The Prometheus `/metrics` endpoint (server.ts:718) is exposed without authentication. It reveals HTTP request counts, file upload counts/errors, error rates by status code, and internal application metrics, allowing infrastructure mapping and targeted attack timing.

**Current state:** No authentication on `/metrics`. Any client can retrieve infrastructure telemetry.

→ **Mitigation:** [M-003 — Add Authentication to Admin, Metrics, and Directory Endpoints](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-007 — XXE via XML File Upload (Arbitrary File Read)

**Scenario:** XXE in `routes/fileUpload.ts:83`: `libxml.parseXml()` is called with `noent: true` (external entity resolution enabled). An attacker uploads an XML file containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to read arbitrary files from the server filesystem, potentially including the SQLite database file or environment variables.

**Current state:** `libxml.parseXml` called with `noent: true` in routes/fileUpload.ts:83. No input size or entity limits configured.

→ **Mitigation:** [M-005 — Harden File Upload — Disable XXE and Fix Path Traversal](#m-005)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-009 — RCE via vm.runInContext in B2B Order Processing

**Scenario:** RCE potential in `routes/b2bOrder.ts:24`: user-supplied `orderLinesData` is executed via `vm.runInContext('safeEval(orderLinesData)', sandbox)`. While `notevil` attempts to sandbox execution, Node.js `vm` module is not a security boundary. An attacker with JWT authentication can supply code to escape the sandbox and execute arbitrary commands on the server.

**Current state:** JWT authentication required, `notevil` sandbox and `vm.runInContext` timeout present, but these are not security boundaries — sandbox escape is documented.

→ **Mitigation:** [M-006 — Remove eval() and vm.runInContext with User-Supplied Code](#m-006)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-011 — Server-Side Template Injection via eval() in User Profile

**Scenario:** SSTI/eval in `routes/userProfile.ts:63`: username values matching `#{...}` pattern are passed directly to `eval()`. An authenticated attacker sets their username to `#{require('child_process').execSync('id').toString()}` and visits `/profile` to execute arbitrary Node.js code on the server, achieving full remote code execution with the process owner's privileges (UID 65532).

**Current state:** JWT authentication required; only triggered if challenge is enabled — but the eval() code path exists unconditionally in userProfile.ts:63.

→ **Mitigation:** [M-006 — Remove eval() and vm.runInContext with User-Supplied Code](#m-006)

---
## 10. Mitigation Register

### <a id="m-001"></a>M-001 · Move JWT Private Key to Environment Variable or Secret Manager

**Addresses:** [T-001](#t-001)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** The hardcoded private key means any developer, CI runner, or external contributor can forge admin JWTs. Rotating it requires a code change and re-deployment.

**How:**
1. Remove the hardcoded private key from `lib/insecurity.ts:23`
2. Generate a new RSA-2048 key pair: `openssl genrsa -out jwt-private.pem 2048 && openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem`
3. Store the private key in a secret manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secret)
4. Load at runtime: `const privateKey = process.env.JWT_PRIVATE_KEY || fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE, 'utf8')`
5. Rotate the key immediately — any tokens signed with the old key are permanently compromised

```typescript
// Before (lib/insecurity.ts:23):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIIC...'

// After:
const privateKey = process.env.JWT_PRIVATE_KEY ??
  fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE ?? '/run/secrets/jwt-private-key', 'utf8')
if (!privateKey || privateKey.startsWith('-----BEGIN') === false) {
  throw new Error('JWT_PRIVATE_KEY not configured — refusing to start')
}
```

**Reference:** [CWE-321](https://cwe.mitre.org/data/definitions/321.html) — Use of Hard-coded Cryptographic Key

---

### <a id="m-002"></a>M-002 · Replace Implicit OAuth Flow with Authorization Code + PKCE

**Addresses:** [T-002](#t-002)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** Implicit flow (`response_type=token`) exposes the access token in the URL fragment where it leaks to browser history, Referer headers, and server logs. It is deprecated per RFC 9700 (OAuth 2.0 Security Best Current Practice).

**How:**
1. Replace `response_type=token` with `response_type=code` in the Google OAuth redirect
2. Implement PKCE: generate `code_verifier` and `code_challenge` (S256) on the frontend
3. Validate the `state` parameter on callback to prevent CSRF
4. Exchange the code for tokens server-side (or use `@angular/fire` / `angular-oauth2-oidc` with PKCE support)
5. Replace the deterministic password derivation `btoa(email.reverse())` with a proper user lookup

```typescript
// Generate PKCE code verifier and challenge
const codeVerifier = crypto.getRandomValues(new Uint8Array(32));
const codeChallenge = await crypto.subtle.digest('SHA-256', codeVerifier);
const state = crypto.randomUUID();
sessionStorage.setItem('pkce_verifier', btoa(String.fromCharCode(...codeVerifier)));
sessionStorage.setItem('oauth_state', state);
// Build auth URL with response_type=code&code_challenge=...&code_challenge_method=S256&state=...
```

**Reference:** [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700), [OWASP OAuth2 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

---

### <a id="m-003"></a>M-003 · Add Authentication to Admin, Metrics, and Directory Endpoints

**Addresses:** [T-003](#t-003), [T-004](#t-004), [T-017](#t-017), [T-018](#t-018)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** `/rest/admin/*`, `/metrics`, `/support/logs`, and `/encryptionkeys` are accessible to any unauthenticated user, leaking configuration, infrastructure topology, access logs with passwords, and cryptographic keys.

**How:**
1. Add `security.isAuthorized()` + admin role check before each admin endpoint registration
2. Restrict `/metrics` to an internal network range or behind HTTP Basic Auth
3. Remove or password-protect the `/support/logs` directory listing
4. Remove the `/encryptionkeys` directory listing — serve only the JWT public key via a dedicated API endpoint if needed
5. Remove or authenticate the `/api-docs` Swagger UI

```typescript
// Before (server.ts:604-605):
app.get('/rest/admin/application-version', retrieveAppVersion())
app.get('/rest/admin/application-configuration', retrieveAppConfiguration())

// After:
app.get('/rest/admin/application-version', security.isAuthorized(), security.isAdmin(), retrieveAppVersion())
app.get('/rest/admin/application-configuration', security.isAuthorized(), security.isAdmin(), retrieveAppConfiguration())

// Before (server.ts:718):
app.get('/metrics', metrics.serveMetrics())

// After:
app.get('/metrics', IpFilter(['127.0.0.1', '::1'], { mode: 'allow' }), metrics.serveMetrics())
```

**Reference:** [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

### <a id="m-004"></a>M-004 · Replace Raw SQL with Parameterized Queries

**Addresses:** [T-005](#t-005), [T-006](#t-006)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** SQL injection in login enables complete authentication bypass. SQL injection in search enables full user table extraction. Both vulnerabilities arise from the same root cause: user input interpolated into SQL strings.

**How:**
1. Replace template literal SQL in `routes/login.ts:44` with Sequelize bound parameters
2. Replace template literal SQL in `routes/search.ts:24` with `Op.like` Sequelize operator
3. Audit all other `sequelize.query()` calls for similar patterns

```typescript
// Before (routes/login.ts:44):
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })

// After:
models.sequelize.query(
  'SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL',
  { bind: [req.body.email || '', security.hash(req.body.password || '')], model: UserModel, plain: true }
)

// Before (routes/search.ts:24):
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

// After:
ProductModel.findAll({ where: { [Op.or]: [{ name: { [Op.like]: `%${criteria}%` } }, { description: { [Op.like]: `%${criteria}%` } }], deletedAt: null }, order: [['name', 'ASC']] })
```

**Reference:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

---

### <a id="m-005"></a>M-005 · Harden File Upload — Disable XXE and Fix Path Traversal

**Addresses:** [T-007](#t-007), [T-008](#t-008)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** XXE in XML upload leaks arbitrary server files. ZIP path traversal allows writing files outside the intended directory. Both arise from insufficient input processing in the file upload handler.

**How:**
1. For XML: disable external entity resolution by removing `noent: true` — use `libxml.parseXml(data, { noent: false, noblanks: true, nocdata: true })`
2. For ZIP: canonicalize the extracted path and reject entries that resolve outside the target directory:
   ```typescript
   const targetDir = path.resolve('uploads/complaints/')
   const absolutePath = path.resolve(targetDir, entry.path)
   if (!absolutePath.startsWith(targetDir + path.sep)) { entry.autodrain(); return; }
   ```
3. Add MIME type validation using the `file-type` library (already in dependencies) instead of extension-only checks

**Reference:** [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

### <a id="m-006"></a>M-006 · Remove eval() and vm.runInContext with User-Supplied Code

**Addresses:** [T-009](#t-009), [T-011](#t-011)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** `vm.runInContext` is not a security boundary — Node.js VM module provides no sandbox isolation. `notevil` has known bypass techniques. `eval()` on user-controlled username is direct RCE. Both patterns allow arbitrary server-side code execution.

**How:**
1. For B2B orders (`routes/b2bOrder.ts`): Replace `vm.runInContext(safeEval(orderLinesData))` with a strict JSON parser: `JSON.parse(orderLinesData)` with schema validation (e.g., `jsonschema` or `zod`)
2. For user profile (`routes/userProfile.ts`): Remove the `if (username?.match(/#{(.*)}/) !== null)` branch entirely and always escape the username before template substitution
3. Never use `eval()`, `new Function()`, or `vm.runInContext()` with user-supplied strings

```typescript
// Before (routes/userProfile.ts:63):
const code = username?.substring(2, username.length - 1)
username = eval(code)

// After: sanitize before template insertion, no eval
username = entities.encode(username ?? '')
template = template.replace(/_username_/g, username)
```

**Reference:** [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

---

### <a id="m-007"></a>M-007 · Add URL Validation to Prevent SSRF in Profile Image Upload

**Addresses:** [T-010](#t-010)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** `fetch(url)` with a user-controlled URL allows probing internal services, cloud metadata endpoints, and local ports. The AWS metadata endpoint `169.254.169.254` can expose IAM credentials in cloud environments.

**How:**
1. Parse and validate the URL before fetching: only allow `http:` and `https:` schemes
2. Resolve the hostname to IP and block private/loopback ranges (RFC 1918, 169.254.0.0/16, ::1)
3. Set a strict allowlist of permitted image hosting domains, or reject all external URLs in favor of a client-side upload-only approach

```typescript
import { isPrivateIp } from 'is-private-ip' // or implement RFC1918 check
const parsed = new URL(url)
if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid scheme')
const { address } = await dns.promises.lookup(parsed.hostname)
if (isPrivateIp(address)) throw new Error('SSRF: private IP blocked')
```

**Reference:** [CWE-918](https://cwe.mitre.org/data/definitions/918.html), [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

### <a id="m-008"></a>M-008 · Store JWT in HttpOnly Cookie — Remove from localStorage

**Addresses:** [T-012](#t-012)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** localStorage is accessible to all JavaScript on the page, including injected XSS payloads. Storing JWT there makes any XSS vulnerability an immediate account takeover.

**How:**
1. Change the login response to set an `HttpOnly; Secure; SameSite=Strict; Path=/` cookie instead of returning the token in the response body
2. Remove `localStorage.setItem('token', ...)` from all Angular components
3. Update the HTTP interceptor to remove the manual `Authorization: Bearer` header — the browser will send the cookie automatically
4. Add CSRF protection (double-submit cookie pattern or synchronizer token) since cookies are sent automatically

```typescript
// Backend (routes/login.ts) - set cookie instead of returning token in body:
res.cookie('token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 6 * 60 * 60 * 1000 // 6 hours
})
res.json({ authentication: { bid: basket.id, umail: user.data.email } }) // no token in body
```

**Reference:** [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

### <a id="m-009"></a>M-009 · Remove bypassSecurityTrustHtml — Use Angular Data Binding

**Addresses:** [T-013](#t-013)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** `bypassSecurityTrustHtml()` disables Angular's built-in XSS protection for the affected element. Every call is a potential stored XSS vector.

**How:**
1. Remove all calls to `this.sanitizer.bypassSecurityTrustHtml()` from Angular components
2. Replace with Angular's standard data binding `{{ value }}` or `[textContent]="value"` which auto-encodes
3. Where HTML rendering is genuinely needed (e.g., rich text comments), use a client-side HTML sanitizer like DOMPurify: `DomPurify.sanitize(html, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] })`
4. Add a Content Security Policy header to reduce XSS impact if any bypass remains

```typescript
// Before (search-result.component.ts:132):
tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)

// After:
tableData[i].description = tableData[i].description // use {{ description }} in template, Angular encodes it
// In template: <td>{{ product.description }}</td>  NOT <td [innerHTML]="product.description">
```

**Reference:** [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

---

### <a id="m-010"></a>M-010 · Replace MD5 with bcrypt or Argon2 for Password Hashing

**Addresses:** [T-014](#t-014)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** MD5 without salt can be cracked at 60+ billion hashes/second on commodity GPUs. It provides zero protection against offline attacks. Once the database is extracted via SQL injection, all passwords are immediately compromised.

**How:**
1. Install `bcryptjs` or `argon2` package
2. Replace `security.hash(password)` in `lib/insecurity.ts:46` and `models/user.ts:57` with bcrypt: `bcrypt.hash(password, 12)`
3. Update the login comparison from hash comparison to `bcrypt.compare(plaintext, stored_hash)`
4. On next login, silently re-hash existing MD5 passwords with bcrypt (migration pattern)

```typescript
// Before (lib/insecurity.ts:46):
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After:
import bcrypt from 'bcryptjs'
export const hashPassword = async (data: string) => bcrypt.hash(data, 12)
export const verifyPassword = async (data: string, hash: string) => bcrypt.compare(data, hash)
// Keep legacy MD5 hash() for non-password uses but rename to clarify
export const md5 = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [CWE-916](https://cwe.mitre.org/data/definitions/916.html)

---

### <a id="m-011"></a>M-011 · Fix CSRF and Enforce POST for Password Change

**Addresses:** [T-015](#t-015), [T-021](#t-021)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Password change over GET is CSRF-trivial (any `<img src="...">` tag triggers it). Missing current-password check allows token-bearing attackers to permanently lock out users.

**How:**
1. Change password endpoint from GET to POST: `app.post('/rest/user/change-password', changePassword())`
2. Move password fields from query params to request body
3. Require `current` password to be present and valid for ALL password changes (remove the falsy-check bypass)
4. Add CSRF token middleware (`csrf-csrf` package) or set `SameSite=Strict` on auth cookies
5. Set CORS to explicit origin allowlist instead of wildcard

```typescript
// Before (routes/changePassword.ts:38):
if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
  // if currentPassword is empty/undefined, this check is skipped!

// After:
if (!currentPassword) {
  res.status(401).send('Current password is required.')
  return
}
if (security.hash(currentPassword) !== loggedInUser.data.password) {
  res.status(401).send('Current password is not correct.')
  return
}
```

**Reference:** [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

### <a id="m-012"></a>M-012 · Add Resource Ownership Verification to Basket and User Endpoints

**Addresses:** [T-016](#t-016)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Any authenticated user can access any other user's basket by guessing the basket ID. The current "check" only detects the challenge as solved — it does not deny access.

**How:**
1. In `routes/basket.ts`: compare the JWT user's `bid` (basket ID from token) against the requested basket ID and return 403 if they don't match
2. Apply the same ownership check to `GET/PUT /api/Users/:id` and `DELETE /api/Users/:id`

```typescript
// Before (routes/basket.ts:22):
challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
  return user && id && user.bid && user?.bid != parseInt(id, 10)
})
// No return/denial — falls through to serve the basket!

// After:
const user = security.authenticatedUsers.from(req)
if (!user || user.bid !== parseInt(id, 10)) {
  return res.status(403).json({ error: 'Forbidden: you can only access your own basket' })
}
```

**Reference:** [OWASP IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html)

---

### <a id="m-013"></a>M-013 · Add Rate Limiting to Login Endpoint

**Addresses:** [T-019](#t-019)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Unlimited login attempts enable brute-force and credential stuffing attacks. The existing rate limit on reset-password demonstrates the pattern is known.

**How:**
1. Apply `express-rate-limit` to `POST /rest/user/login` — 10 attempts per 15 minutes per IP
2. Implement account lockout after 10 failed attempts (store in cache/DB)
3. Add exponential backoff responses (429 with `Retry-After` header)

```typescript
// Add before route definition (server.ts, near line 594):
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many login attempts, please try again in 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
})
app.post('/rest/user/login', loginLimiter, login())
```

**Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

### <a id="m-014"></a>M-014 · Enforce Payload Size Limits on All Endpoints

**Addresses:** [T-020](#t-020), [T-026](#t-026)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** YAML bombs and oversized JSON bodies can exhaust server memory and CPU, causing denial of service.

**How:**
1. Add `limit` option to `bodyParser.json()`: `bodyParser.json({ limit: '1mb' })`
2. Add multer file size limit: `multer({ limits: { fileSize: 10 * 1024 * 1024 } })` (10MB)
3. Upgrade `js-yaml` to v4.x which defaults to safe load (no aliases/anchors by default)
4. For XML: add libxml node count/depth limit

**Reference:** [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

---

### <a id="m-015"></a>M-015 · Implement Structured Security Event Logging

**Addresses:** [T-022](#t-022)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Without security event logging, successful attacks leave no forensic trail. Compliance requirements (SOC 2, PCI-DSS) mandate logging of authentication events.

**How:**
1. Configure Winston with JSON format: `winston.format.json()` instead of `simple()`
2. Add file transport: `new winston.transports.File({ filename: 'logs/security.json' })`
3. Log structured events at key points: login success/failure, password change, privilege escalation, data export
4. Never log sensitive values (passwords, tokens, PII) — log user ID and action only

```typescript
// In routes/login.ts, after authentication result:
logger.info(JSON.stringify({
  event: 'authentication',
  outcome: user.data?.id ? 'success' : 'failure',
  userId: user.data?.id,
  email: req.body.email?.replace(/./g, '*'), // redact
  ip: req.ip,
  timestamp: new Date().toISOString()
}))
```

**Reference:** [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

### <a id="m-016"></a>M-016 · Fix Open Redirect — Use Exact Match Instead of substring includes

**Addresses:** [T-023](#t-023)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** `url.includes(allowedUrl)` can be bypassed by embedding the allowed URL as a substring of a malicious URL.

**How:**
1. Replace `url.includes(allowedUrl)` with exact URL matching or a `startsWith` check combined with pathname-only matching
2. Or better: use a validated allowlist and do exact matching: `allowedUrls.has(url)`

```typescript
// Before (lib/insecurity.ts - isRedirectAllowed):
allowed = allowed || url.includes(allowedUrl) // VULNERABLE

// After:
allowed = allowed || url === allowedUrl || url.startsWith(allowedUrl + '/')
```

**Reference:** [CWE-601](https://cwe.mitre.org/data/definitions/601.html)

---

### <a id="m-017"></a>M-017 · Replace Development Error Handler with Production Handler

**Addresses:** [T-024](#t-024)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** The `errorhandler` npm package is the Express development error handler that sends full stack traces to HTTP clients — it is explicitly documented as not for production use.

**How:**
1. Remove `const errorhandler = require('errorhandler')` and `app.use(errorhandler())`
2. Replace with a production error handler that logs details server-side and returns generic messages

```typescript
// Before (server.ts:676):
app.use(errorhandler())

// After:
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error(JSON.stringify({ event: 'unhandled_error', message: err.message, stack: err.stack, path: req.path }))
  res.status(500).json({ error: 'An unexpected error occurred' })
})
```

**Reference:** [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html)

---

### <a id="m-018"></a>M-018 · Add package-lock.json and Pin Dependency Versions

**Addresses:** [T-025](#t-025)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Without a lockfile, `npm install` can silently pull in a different (potentially compromised) version of any dependency. The caret ranges allow minor/patch version changes that may include malicious code.

**How:**
1. Run `npm install` to generate `package-lock.json` and commit it to the repository
2. Consider using `npm ci` in CI/CD instead of `npm install` to enforce lockfile integrity
3. Enable Dependabot or Renovate for automated dependency updates with lockfile maintenance
4. Add `npm audit` to the CI pipeline as a blocking step

**Reference:** [OWASP Vulnerable Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

---

## 11. Out of Scope

The following areas were not fully analyzed in this assessment:

- **Intentional challenge implementations** — All `challengeUtils.solveIf()` logic and challenge-specific code paths are out of scope. The vulnerabilities they introduce are documented elsewhere in this report but analyzed as architectural issues.
- **WebSocket/socket.io event security** — Basic analysis only; full event payload fuzzing not performed.
- **Ethereum/Web3 contract interaction** — The blockchain interaction logic (`routes/nftMint.ts`, `routes/web3Wallet.ts`) was not fully analyzed. Known risk: no validation on contract addresses supplied by users.
- **MarsDB security** — The in-process MarsDB collections (orders, reviews) were not analyzed for NoSQL injection beyond surface review.
- **Frontend build pipeline** — Angular build configuration, tree-shaking, and production bundle hardening not analyzed.
- **Third-party Angular dependencies** — Only core Angular dependencies reviewed; third-party Angular modules not audited.
- **Chatbot NLP security** — The `juicy-chat-bot` library's NLP attack surface (adversarial input, training data poisoning) was not analyzed.
- **GDPR/data erasure flow** — The `/dataerasure` HBS form was identified as a CSRF target but the full data lifecycle was not traced.
- **Cryptocurrency donation redirect** — The redirect to crypto wallet addresses is an intentional challenge feature; not re-analyzed.
- **YAML upload content** — Beyond the YAML bomb DoS, the YAML upload schema validation was not fully audited.
- **Components scoped out**: The recycle, delivery, and wallet balance routes were reviewed at a surface level only.
