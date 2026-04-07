# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-06T20:10:00Z |
| Analysis Duration | 12 min 42 s |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Input Tokens | unavailable |
| Output Tokens | unavailable |
| Cache Read Tokens | unavailable |
| Cache Write Tokens | unavailable |
| Estimated Cost | unavailable |
| Context Sources | None |

> Token and cost data are not accessible at agent runtime. Check the Anthropic Console for usage details of this session.

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
8. [Threat Register](#8-threat-register)
9. [Critical Findings](#9-critical-findings)
10. [Mitigation Register](#10-mitigation-register)
11. [Out of Scope](#11-out-of-scope)

---

## 1. System Overview

**OWASP Juice Shop** (`juice-shop` v19.2.1) is an intentionally insecure web application used for security awareness training, Capture The Flag (CTF) competitions, and penetration testing practice. It is the flagship project of the Open Worldwide Application Security Project (OWASP) and deliberately implements well-known web application vulnerabilities as trainable challenge scenarios.

**Repository:** https://github.com/juice-shop/juice-shop  
**Team Owner:** OWASP / Björn Kimminich  
**Asset Classification:** Tier 1 (Training / CTF platform — public exposure intended)  
**Compliance Scope:** OWASP Top 10, General Web Application Security

**Technology Stack:**
- **Backend:** Node.js 20-24, TypeScript 5.3, Express 4.22, Sequelize 6 ORM
- **Databases:** SQLite 3 (primary, Sequelize), MarsDB (NoSQL in-memory for reviews/orders)
- **Frontend:** Angular 20, TypeScript
- **Authentication:** Custom JWT (jsonwebtoken 0.4.0, express-jwt 0.1.3 — extremely outdated)
- **Containerization:** Docker (distroless/nodejs24-debian13 base image, UID 65532)
- **CI/CD:** GitHub Actions (CodeQL SAST, ZAP DAST weekly, CycloneDX SBOM)
- **Monitoring:** Prometheus / prom-client 14

**Deployment Context:** Designed to run as a single container or directly with Node.js. Docker image uses distroless base with non-root user (UID 65532). No Kubernetes manifests or cloud-provider-specific configs were found — deployable anywhere.

**Complexity Tier Selected: Moderate** — single deployable Node.js application with two data stores (SQLite + MarsDB), a built-in Angular SPA served from the same process, and several external integration points (Web3/blockchain, chatbot, file uploads). A Context diagram and Container diagram capture the architecture fully.

**Business Context:**  
The application simulates a juice shop e-commerce site with users, products, orders, payments, user profiles, an administrative interface, a customer support chatbot, and a crypto/Web3 wallet feature. **Critically, many of the vulnerabilities documented in this threat model are intentional challenge implementations.** Each threat is rated on its objective technical severity; the "intentional" nature is noted but does not reduce the rating since this platform may be deployed in environments where trainees could inadvertently expose real infrastructure.

**Overall Security Impression:**  
The codebase contains a dense concentration of deliberately implemented critical and high-severity vulnerabilities: raw SQL string interpolation enabling SQL injection in both the login and search endpoints; MD5 password hashing; a hardcoded RSA private key embedded in source code; wildcard CORS; JWT tokens stored in `localStorage`; multiple `bypassSecurityTrustHtml` calls bypassing Angular's XSS protections; an XXE-enabled XML upload handler; an RCE-capable B2B order evaluation endpoint; and SSRF via profile image URL upload. These are not side-effects of poor development — they are intentional training constructs. From a pure security architecture perspective, this system represents a comprehensive catalogue of anti-patterns.

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
        TRAINEE["Trainee / Attacker\nSecurity Student\nCTF Participant"]:::person
        ADMIN_USER["Admin / Instructor\nApplication Admin\nJuice Shop Account"]:::person
        EXTBOT["Automated Scanner\nZAP / Burp / Bots\nUnauthenticated"]:::external
    end

    subgraph INTERNAL["🔒 Deployment Zone · operator-controlled"]
        JUICESHOP["OWASP Juice Shop\nNode.js 20-24 + Angular 20\nExpress 4.22 · TypeScript 5.3\nDocker · UID 65532 · port 3000"]:::system
    end

    subgraph EXTERNAL_SVC["🌐 External Services"]
        BLOCKCHAIN["Blockchain APIs\nEtherscan / Dash Explorer\nRead-only queries"]:::external
        GITHUB_CDN["GitHub / CDN\nChatbot training data\nDownloaded at startup"]:::external
    end

    TRAINEE -->|"HTTPS · GET/POST · port 3000"| JUICESHOP
    ADMIN_USER -->|"HTTPS · GET/POST · port 3000"| JUICESHOP
    EXTBOT -->|"HTTP · automated scans (unauth)"| JUICESHOP
    JUICESHOP -->|"HTTPS · wallet/NFT queries"| BLOCKCHAIN
    JUICESHOP -->|"HTTPS · download training JSON"| GITHUB_CDN

%% Trust Boundary Key:
%% 🌐 Public Internet → 🔒 Deployment Zone: No WAF/CDN by default; only application-level controls
%% 🔒 Deployment Zone → 🌐 External Services: Outbound HTTPS; no mTLS; SSRF risk on profile URL upload
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
        BROWSER["Browser / Client\nAngular 20 SPA\nToken in localStorage"]:::person
    end

    subgraph APP_LAYER["🔶 Application Layer · Docker UID 65532"]
        EXPRESS["Express REST API\nNode.js 20 · TypeScript 5.3\nExpress 4.22 · port 3000\nHelmet partial · CORS wildcard"]:::risk
        ANGULAR_DIST["Angular SPA Bundle\nAngular 20\nServed as static files\nNo BFF · tokens in localStorage"]:::risk
        CHATBOT["Chatbot Engine\njuicy-chat-bot ~0.9\nNo auth on status endpoint\nTraining data downloaded"]:::system
        METRICS["Prometheus Metrics\nprom-client 14\nExposed on /metrics\nNo auth guard"]:::risk
        SWAGGER["Swagger UI\nswagger-ui-express 5\nFull API docs at /api-docs\nNo auth guard"]:::risk
        FILESTORE["File System Storage\nUploads · FTP directory\nLogs · Encryption keys\nPublicly browsable"]:::risk
    end

    subgraph DB_TIER["🔐 Data Tier · restricted"]
        SQLITE["SQLite Database\nsequelize 6.37\nFile-based · no auth\nRaw SQL in login+search"]:::risk
        MARSDB["MarsDB In-Memory\nmarsdb 0.6.11\nNoSQL · reviews+orders\nNo query sanitization"]:::risk
    end

    BROWSER -->|"HTTPS · GET /api/* REST"| EXPRESS
    BROWSER -->|"HTTPS · GET static files"| ANGULAR_DIST
    BROWSER -->|"WebSocket · Socket.io 3"| EXPRESS
    EXPRESS -->|"Sequelize ORM · SQL · file"| SQLITE
    EXPRESS -->|"MarsDB API · in-memory"| MARSDB
    EXPRESS -->|"Static serve"| ANGULAR_DIST
    EXPRESS -->|"reads/writes"| FILESTORE
    EXPRESS -->|"scrapes metrics"| METRICS
    EXPRESS -->|"hosts API docs"| SWAGGER
    EXPRESS -->|"processes queries"| CHATBOT

%% Trust Boundary Key:
%% 🌐 Public Internet → 🔶 Application Layer: No WAF; application JWT middleware (selective coverage)
%% 🔶 Application Layer → 🔐 Data Tier: No network isolation; same process; raw SQL in two endpoints
```

### 2.3 Technology Architecture

```mermaid
graph TB
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph BROWSER_LAYER["Browser Layer"]
        SPA["Angular 20 SPA\nTypeScript · Angular Router\nHTTP Interceptor adds JWT Bearer\nToken stored in localStorage"]:::risk
    end

    subgraph SERVER_LAYER["Server Layer · Node.js 20 · Express 4.22"]
        MW["Middleware Stack\nHelmet partial · CORS wildcard\ncookieParser · bodyParser\nmorgan access logging"]:::system
        AUTH["Auth Layer\nJWT RS256 (sign)\nexpress-jwt 0.1.3 (verify)\njsonwebtoken 0.4.0\nHardcoded RSA private key"]:::risk
        REST["REST API Routes\n/rest/** · /api/** · /b2b/**\nfinale-rest CRUD generator\nSequelize + raw SQL"]:::risk
        FILE_UPLOAD["File Upload Handler\nmulter · XML+YAML+ZIP parsing\nXXE via libxmljs2\nPath traversal risk"]:::risk
        CHATBOT_SVC["Chatbot Service\njuicy-chat-bot\nTraining data from URL\nNo input sanitization"]:::system
        METRICS_SVC["Metrics Service\nprom-client 14\nPrometheus format\nNo auth guard"]:::risk
    end

    subgraph DATA_LAYER["Data Layer"]
        SQLITE_DB[("SQLite 3\nsequelize 6\nRaw SQL interpolation\nin login + search")]:::risk
        MARSDB_STORE[("MarsDB In-Memory\nReviews + Orders\nNoSQL injection risk")]:::risk
        FS_STORE["File System\nuploads/ · ftp/\nencryptionkeys/ · logs/\nAll publicly browsable"]:::risk
    end

    SPA -->|"HTTPS · Bearer JWT · /api/*"| MW
    MW -->|"JWT verify · RS256 public key"| AUTH
    AUTH -->|"next() or 401"| REST
    REST -->|"Sequelize ORM · raw SQL"| SQLITE_DB
    REST -->|"MarsDB query"| MARSDB_STORE
    REST -->|"write/read files"| FS_STORE
    MW -->|"file upload · multipart"| FILE_UPLOAD
    FILE_UPLOAD -->|"write to uploads/"| FS_STORE
    REST -->|"query"| CHATBOT_SVC
    REST -->|"observe"| METRICS_SVC
```

### 2.4 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ❌ | No dedicated gateway; Express routes are the only entry point |
| BFF (Backend for Frontend) | ❌ | SPA communicates directly with REST API; JWT stored in `localStorage` |
| Defense in Depth | ❌ | Single application layer; no WAF, no rate limiting on login endpoint, no CSP |
| Separation of Concerns | ⚠️ | Routes are separated by file; but auth, data access, and business logic mix freely |
| Least Privilege | ⚠️ | Docker runs as UID 65532 (good); but app-level roles not enforced on `PUT /api/Products/:id` |
| Secrets Management | ❌ | RSA private key hardcoded in [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23); cookie secret `'kekse'` hardcoded in [`server.ts:289`](vscode://file/root/juice-shop/server.ts:289) |
| Network Segmentation | ❌ | SQLite and MarsDB share the same process; no network-level isolation |
| Secure Defaults | ❌ | CORS wildcard, XSS filter commented out, `/metrics` unauthenticated, FTP browseable |

#### Trust Model Evaluation

The application does not implement a fail-closed trust model. The application layer applies JWT middleware selectively — several high-sensitivity routes (`/rest/products/search`, `/rest/chatbot/respond`, `/rest/chatbot/status`, `/api/Feedbacks POST`, `/rest/user/reset-password`, `/api-docs`) are reachable without authentication. The data tier has no separate trust boundary: SQLite and MarsDB are embedded within the same Node.js process and are accessed directly from route handlers, meaning any SQL or NoSQL injection in a route directly reaches the database.

The "public internet to application" boundary has no WAF, no CDN, and by default no TLS termination proxy — the Express server serves HTTP directly. An attacker on the public internet has direct access to all application endpoints.

#### Authentication and Authorization Architecture

- **Protocol:** Custom JWT-based session using RS256 signing. Tokens are issued by `security.authorize()` ([`lib/insecurity.ts:56`](vscode://file/root/juice-shop/lib/insecurity.ts:56)) and stored by the client in `localStorage`.
- **IdP:** No external identity provider. Authentication is entirely self-managed using `jsonwebtoken 0.4.0` (released ~2014) and `express-jwt 0.1.3` (extremely outdated).
- **Critical structural flaw:** The RSA private key is hardcoded in source code ([`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23)), meaning any user can forge valid JWT tokens by signing with the extracted private key.
- **Password hashing:** MD5 is used ([`lib/insecurity.ts:43`](vscode://file/root/juice-shop/lib/insecurity.ts:43)), which is a cryptographically broken algorithm for password storage — not a work-factor function like bcrypt/Argon2.
- **Authorization:** Role checks (`isAccounting`, `isDeluxe`, `isCustomer`) are implemented inline in route middleware. There is no centralized authorization enforcement layer.
- **TOTP:** Optional 2FA via `otplib` is supported ([`routes/2fa.ts`](vscode://file/root/juice-shop/routes/2fa.ts)) with rate limiting, which is the strongest auth control present.
- **Token storage:** JWT is stored in `localStorage` by the Angular SPA ([`frontend/src/app/Services/request.interceptor.ts:13`](vscode://file/root/juice-shop/frontend/src/app/Services/request.interceptor.ts:13)), making it accessible to any XSS payload.

#### Key Architectural Risks

| # | Structural Risk | Impact if Exploited | Linked Threats |
|---|----------------|---------------------|----------------|
| 1 | RSA private key hardcoded in source code — any user can forge admin-level JWTs | Full authentication bypass; any account impersonation | T-001 |
| 2 | No BFF pattern — JWT lives in `localStorage` and is readable by any XSS script | Token theft enables session hijacking without any server-side invalidation | T-007, T-008 |
| 3 | Wildcard CORS (`Access-Control-Allow-Origin: *`) with no credential restriction | Cross-origin requests can read all API responses from any attacker-controlled page | T-013 |
| 4 | Raw SQL string interpolation in login and search routes — no parameterization | Authentication bypass and full database extraction via UNION injection | T-002, T-003 |
| 5 | Unauthenticated sensitive endpoints: `/metrics`, `/api-docs`, `/ftp`, `/support/logs`, `/encryptionkeys` | Infrastructure topology disclosure; access-log exfiltration; private key access | T-010, T-011 |

#### Overall Architecture Security Rating

🔴 **Critical gaps** — This application has fundamental, architectural-level security failures across all major security domains: authentication (hardcoded private key), authorization (missing checks on state-changing endpoints), data protection (MD5 passwords, raw SQL), frontend security (XSS bypasses, localStorage tokens), and infrastructure (wildcard CORS, unauthenticated internal endpoints). While these are intentional for training purposes, any deployment of this application in a network-accessible environment without isolation poses severe risk of lateral movement and credential compromise.

---

## 3. Security-Relevant Use Cases

### 3.1 Input Validation Flow

```mermaid
sequenceDiagram
    participant User as User/Attacker
    participant SPA as Angular SPA
    participant API as Express API
    participant DB as SQLite DB

    User->>SPA: Enter search query in input field
    SPA->>API: GET /rest/products/search?q=user_input
    Note over API: NO input sanitization<br/>criteria = req.query.q (raw string)
    API->>DB: SELECT * FROM Products WHERE name LIKE '%user_input%'
    Note over DB: Raw string interpolation<br/>routes/search.ts:23<br/>UNION injection possible
    DB-->>API: Result set (may include injected data)
    API-->>SPA: JSON response
    SPA->>SPA: bypassSecurityTrustHtml(description)
    Note over SPA: search-result.component.ts:132<br/>Angular XSS protection disabled
    SPA-->>User: Rendered HTML (XSS possible)
```

### 3.2 Frontend Security (XSS)

```mermaid
sequenceDiagram
    participant Attacker as Attacker
    participant API as Express API
    participant Admin as Admin Browser
    participant Angular as Angular Renderer

    Attacker->>API: POST /api/Feedbacks (unauthenticated)<br/>body: {comment: "<script>payload</script>"}
    Note over API: No output encoding<br/>sanitize-html 1.4.2 (outdated, bypassable)
    API-->>Attacker: 201 Created - feedback stored

    Admin->>API: GET /api/Feedbacks
    API-->>Admin: JSON with raw HTML in comment field
    Admin->>Angular: Render feedback list
    Angular->>Angular: sanitizer.bypassSecurityTrustHtml(feedback.comment)
    Note over Angular: about.component.ts:119<br/>administration.component.ts:78<br/>Angular sanitization disabled!
    Angular-->>Admin: XSS payload executes
    Note over Admin: localStorage.getItem('token') readable<br/>by attacker's injected script
```

### 3.3 Database Security (SQL Injection)

```mermaid
sequenceDiagram
    participant Attacker as Attacker
    participant API as Express API
    participant SQLite as SQLite DB

    Attacker->>API: POST /rest/user/login<br/>body: {email: "' OR 1=1--", password: "x"}
    Note over API: routes/login.ts:34<br/>Template literal SQL construction<br/>NO parameterization

    API->>SQLite: SELECT * FROM Users WHERE email = '' OR 1=1--'<br/>AND password = '...' AND deletedAt IS NULL
    SQLite-->>API: First user record (admin)
    API-->>Attacker: 200 OK + JWT token for admin user

    Attacker->>API: GET /rest/products/search?q=' UNION SELECT...<br/>Extracts all user emails and MD5 passwords
    API->>SQLite: Raw interpolated UNION query
    SQLite-->>API: Exfiltrated user data
    API-->>Attacker: Full user database dump
```

### 3.4 Authentication Flow

```mermaid
sequenceDiagram
    participant User as User
    participant SPA as Angular SPA
    participant API as Express API (POST /rest/user/login)
    participant DB as SQLite Users table

    User->>SPA: Enter email + password
    SPA->>API: POST /rest/user/login<br/>{email, password}
    Note over API: routes/login.ts:34<br/>Raw SQL query (SQLi vulnerable)
    API->>DB: SELECT * FROM Users WHERE email='{email}' AND password=MD5('{password}')
    DB-->>API: User record or empty
    alt User has TOTP enabled
        API-->>SPA: 401 {status: "totp_token_required", tmpToken}
        SPA->>API: POST /rest/2fa/verify {tmpToken, totp}
        Note over API: Rate limited: 100/5min
        API-->>SPA: 200 {authentication: {token, bid, umail}}
    else No TOTP
        API-->>SPA: 200 {authentication: {token, bid, umail}}
    end
    SPA->>SPA: localStorage.setItem('token', jwt)
    Note over SPA: request.interceptor.ts:13<br/>Token in localStorage - XSS accessible!
    SPA->>API: Subsequent requests with Authorization: Bearer JWT
```

### 3.5 Authorization / Access Control

```mermaid
sequenceDiagram
    participant User as Authenticated User
    participant API as Express API
    participant AuthMW as Auth Middleware (lib/insecurity.ts)
    participant RouteHandler as Route Handler

    User->>API: PUT /api/Products/1 (no auth middleware on this route!)
    Note over API: server.ts:369 - isAuthorized() commented out!
    API->>RouteHandler: Request passes through without auth check
    RouteHandler-->>User: 200 OK - product modified by any user

    User->>API: PATCH /rest/products/reviews (authorized)
    API->>AuthMW: isAuthorized() - expressJwt({secret: publicKey})
    Note over AuthMW: Verifies JWT signature<br/>No role check - any user can update any review
    AuthMW->>RouteHandler: updateProductReviews()
    Note over RouteHandler: routes/updateProductReviews.ts:18<br/>No author ownership check<br/>NoSQL injection in _id field
    RouteHandler-->>User: Review updated (may belong to other user)
```

### 3.6 Secret Management

```mermaid
sequenceDiagram
    participant Dev as Developer / Attacker
    participant Repo as Git Repository
    participant App as Running Application
    participant EncDir as /encryptionkeys/ (public!)

    Dev->>Repo: git clone https://github.com/juice-shop/juice-shop
    Repo-->>Dev: lib/insecurity.ts with hardcoded RSA private key (line 23)
    Note over Dev: Full private key in source:<br/>-----BEGIN RSA PRIVATE KEY-----<br/>MIICXAIBAAKBgQ...
    Dev->>App: Forge JWT: jwt.sign({role:'admin'}, stolenPrivateKey, {algorithm:'RS256'})
    App-->>Dev: Valid admin JWT accepted by all endpoints

    Dev->>EncDir: GET /encryptionkeys/ (unauthenticated directory listing)
    EncDir-->>Dev: jwt.pub, premium.key
    Dev->>EncDir: GET /encryptionkeys/premium.key
    EncDir-->>Dev: Premium reward decryption key

    Note over App: Cookie secret 'kekse' hardcoded<br/>server.ts:289
```

### 3.7 File Upload Security Flow

```mermaid
sequenceDiagram
    participant Attacker as Attacker
    participant API as Express API (POST /file-upload)
    participant FileHandler as routes/fileUpload.ts
    participant XMLParser as libxmljs2 (noent: true)
    participant FS as File System

    Attacker->>API: POST /file-upload<br/>multipart: malicious.xml with XXE payload
    API->>FileHandler: ensureFileIsPassed -> checkUploadSize -> checkFileType -> handleXmlUpload
    FileHandler->>XMLParser: libxml.parseXml(data, {noent: true})
    Note over XMLParser: fileUpload.ts:83<br/>External entity expansion ENABLED<br/>noent: true = XXE!
    XMLParser-->>FileHandler: Parsed XML with /etc/passwd content
    FileHandler-->>Attacker: 410 error with file contents in error message

    Attacker->>API: POST /profile/image/url<br/>{imageUrl: "http://internal-service/admin"}
    API->>API: fetch(url) - server-side request!
    Note over API: profileImageUrlUpload.ts:24<br/>No URL allowlist - SSRF!
    API-->>Attacker: Internal service response proxied
```

### 3.8 B2B Order - Remote Code Execution Flow

```mermaid
sequenceDiagram
    participant Attacker as Authenticated Attacker
    participant API as Express API (POST /b2b/v2/orders)
    participant VM as Node.js vm.runInContext
    participant System as Host System

    Note over Attacker: Requires valid JWT (any user role)
    Attacker->>API: POST /b2b/v2/orders<br/>{orderLinesData: "while(true){}"}
    Note over API: security.isAuthorized() check passes<br/>Any authenticated user can reach this
    API->>VM: vm.runInContext('safeEval(orderLinesData)', sandbox)
    Note over VM: b2bOrder.ts:21-23<br/>notevil safeEval in vm context<br/>Sandbox escape possible
    VM->>System: JavaScript execution in sandbox
    Note over System: Infinite loop = DoS (rceOccupyChallenge)<br/>Sandbox escape = RCE (rceChallenge)
    System-->>API: Timeout or execution result
    API-->>Attacker: 503 or order response
```

---

## 4. Assets

| Asset | Classification | Description | Linked Threats |
|-------|----------------|-------------|----------------|
| User PII (email, address, payment cards) | Confidential | All registered user email addresses, delivery addresses, and saved payment card data stored in SQLite | [T-002](#t-002), [T-003](#t-003), [T-012](#t-012) |
| User Credentials (passwords) | Restricted | MD5-hashed passwords for all user accounts in the Users table | [T-002](#t-002), [T-003](#t-003), [T-004](#t-004) |
| JWT RSA Private Key | Restricted | Hardcoded RSA private key in `lib/insecurity.ts:23` used to sign all session tokens | [T-001](#t-001) |
| JWT RSA Public Key | Internal | `encryptionkeys/jwt.pub` served via unauthenticated directory listing at `/encryptionkeys/` | [T-010](#t-010) |
| Premium Decryption Key | Restricted | `encryptionkeys/premium.key` served via unauthenticated directory listing | [T-010](#t-010) |
| CTF Key | Restricted | `ctf.key` file in repo root — used to compute CTF flag HMACs | [T-010](#t-010) |
| Session Tokens (JWT) | Confidential | Active JWT tokens stored in browser `localStorage`, accessible to XSS | [T-007](#t-007), [T-008](#t-008) |
| Application Access Logs | Internal | Server access logs in `logs/` directory, browseable at `/support/logs` | [T-011](#t-011) |
| FTP Sensitive Files | Confidential | `acquisitions.md`, `incident-support.kdbx`, `suspicious_errors.yml` in `/ftp/` directory, publicly browseable | [T-010](#t-010) |
| Order / Financial Data | Confidential | Order history, wallet balances, payment processing data in SQLite and MarsDB | [T-002](#t-002), [T-012](#t-012) |
| Application Availability | Internal | Uptime and response time for training sessions/CTF events | [T-015](#t-015), [T-016](#t-016) |
| Source Code / Challenge Logic | Internal | Challenge solutions and vulnerable code snippets exposed via `/snippets/` endpoint | [T-010](#t-010) |

---

## 5. Attack Surface

| Entry Point | Protocol/Method | Authentication | Notes | Linked Threats |
|-------------|----------------|----------------|-------|----------------|
| `POST /rest/user/login` | HTTP POST | None | Raw SQL injection in email/password fields | [T-002](#t-002), [T-006](#t-006) |
| `GET /rest/products/search?q=` | HTTP GET | None (public) | Raw SQL injection in q parameter | [T-003](#t-003) |
| `POST /file-upload` | HTTP POST multipart | None | XML/YAML/ZIP upload with XXE, path traversal, YAML bomb | [T-014](#t-014), [T-015](#t-015) |
| `POST /profile/image/url` | HTTP POST | JWT (cookie) | SSRF via arbitrary URL fetch on server side | [T-012](#t-012) |
| `POST /b2b/v2/orders` | HTTP POST | JWT (any role) | `orderLinesData` evaluated via safeEval in vm sandbox | [T-016](#t-016) |
| `GET /api-docs` | HTTP GET | None | Full Swagger UI + API spec exposed, no auth | [T-010](#t-010) |
| `GET /metrics` | HTTP GET | None | Prometheus metrics with internal app data, no auth | [T-010](#t-010) |
| `GET /ftp/` | HTTP GET | None | Directory listing + file download of sensitive files | [T-010](#t-010) |
| `GET /support/logs` | HTTP GET | None | Access log directory listing and download | [T-011](#t-011) |
| `GET /encryptionkeys/` | HTTP GET | None | Directory listing exposing jwt.pub and premium.key | [T-010](#t-010) |
| `PATCH /rest/products/reviews` | HTTP PATCH | JWT (any role) | NoSQL injection in `_id` field, no ownership check | [T-005](#t-005) |
| `PUT /api/Products/:id` | HTTP PUT | None (commented out) | Auth middleware commented out — any user modifies products | [T-009](#t-009) |
| `POST /api/Feedbacks` | HTTP POST | None | Public — stores unencoded HTML, persisted XSS vector | [T-007](#t-007) |
| `GET /rest/user/change-password` | HTTP GET | JWT (weak check) | Password in query string, no current password required without token | [T-006](#t-006) |
| `GET /rest/user/reset-password` (POST) | HTTP POST | None (security question) | Rate limit uses `X-Forwarded-For` header (spoofable) | [T-006](#t-006) |
| `WebSocket` (Socket.io) | WS | None / JWT | Challenge notification channel | [T-015](#t-015) |
| `GET /redirect?to=` | HTTP GET | None | Open redirect with partial URL matching (includes-based allowlist) | [T-013](#t-013) |
| `POST /rest/chatbot/respond` | HTTP POST | JWT (cookie check) | User-controlled query to chatbot engine | [T-007](#t-007) |
| `GET /rest/admin/application-configuration` | HTTP GET | None | Full app config disclosure, no auth | [T-010](#t-010) |
| `GET /rest/admin/application-version` | HTTP GET | None | Version disclosure, no auth | [T-010](#t-010) |
| `POST /api/Users` | HTTP POST | None | User registration, role field user-controllable | [T-009](#t-009) |
| `GET /snippets/:challenge` | HTTP GET | None | Challenge vulnerable code snippets exposed | [T-010](#t-010) |

---

## 6. Trust Boundaries

The overall trust model is **implicit trust by default with selective denials** — a deeply insecure pattern. The application applies JWT middleware only to specific routes and route groups, leaving many sensitive endpoints entirely open.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|---------|------|----|-----------------------|--------------|----------------|
| 1 | Public Internet to Express API | Any internet client | Express route handlers | None (no WAF, no reverse proxy required) | No TLS enforcement at app layer; no IP allowlisting by default | [T-015](#t-015), [T-016](#t-016) |
| 2 | Unauthenticated to Authenticated | Anonymous user | Protected REST routes | `security.isAuthorized()` via `express-jwt 0.1.3` | Selective application only; many routes not protected; `PUT /api/Products/:id` auth deliberately commented out | [T-009](#t-009), [T-003](#t-003) |
| 3 | Customer to Admin role | Customer-role JWT | Admin-accessible routes | Role check in JWT `data.role` field | JWT private key is hardcoded in source — any user can forge admin role claim | [T-001](#t-001) |
| 4 | Customer to Accounting role | Customer-role JWT | `/rest/order-history/orders`, `/api/Quantitys/:id` | `security.isAccounting()` inline check | Same private key vulnerability applies | [T-001](#t-001) |
| 5 | Application to SQLite | Express routes | SQLite database | Sequelize ORM (partially) | Two raw SQL endpoints (`login`, `search`) bypass the ORM | [T-002](#t-002), [T-003](#t-003) |
| 6 | Application to MarsDB | Express routes | MarsDB in-memory | Direct MarsDB API calls | No input sanitization on `_id` field in reviews update | [T-005](#t-005) |
| 7 | Server to External URLs | App server | External internet | None | `fetch(url)` in `profileImageUrlUpload.ts` allows SSRF to internal services | [T-012](#t-012) |
| 8 | Browser Origin | SPA | Express CORS | `cors()` with no config (wildcard) | `Access-Control-Allow-Origin: *` — any origin can make cross-origin requests | [T-013](#t-013) |

**Prose notes:**
- Boundary 2 is the most critical structural weakness. The `isAuthorized()` middleware is a declaration of intent that is inconsistently applied. For example, `PUT /api/Products/:id` has its auth middleware commented out (server.ts:369), making product modification available to unauthenticated users. The unauthenticated nature of `/api-docs`, `/metrics`, `/ftp`, `/support/logs`, and `/encryptionkeys/` represents a near-total absence of any "internal" data boundary.
- Boundary 8 (CORS wildcard) is particularly dangerous in combination with Boundary 7 (SSRF) and the JWT-in-localStorage pattern: an XSS attacker who steals the token from `localStorage` can make authenticated API requests from any origin.

---

## 7. Identified Security Controls

**Critical gaps summary (top 5):**
1. **Password hashing** uses MD5 — a non-work-factor hash easily crackable with rainbow tables or GPU cracking. No bcrypt/Argon2/scrypt used anywhere.
2. **JWT private key hardcoded in source** — nullifies the entire authentication system since any attacker with code access can forge tokens for any role.
3. **No Content Security Policy** — `helmet.xssFilter()` is commented out; no CSP header is set; Angular's `DomSanitizer.bypassSecurityTrustHtml()` is called in multiple components.
4. **CORS wildcard** — `cors()` with no configuration allows any cross-origin request, removing same-origin policy protections.
5. **Unauthenticated sensitive endpoints** — `/metrics`, `/api-docs`, `/ftp/`, `/support/logs`, `/encryptionkeys/` expose internal data without any access control.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness |
|--------|---------|----------------|---------------|
| **Identity & Access Management** | JWT token issuance | RS256 signing via `jwt.sign()` in [`lib/insecurity.ts:56`](vscode://file/root/juice-shop/lib/insecurity.ts:56) | 🔶 Weak — RS256 algorithm is correct but private key is hardcoded in the same file at line 23 |
| **Identity & Access Management** | JWT token verification | `express-jwt 0.1.3` via `security.isAuthorized()` in [`lib/insecurity.ts:54`](vscode://file/root/juice-shop/lib/insecurity.ts:54) | 🔶 Weak — version 0.1.3 is ~10 years old; no algorithm allowlist configured; `alg:none` attack may be possible |
| **Identity & Access Management** | TOTP 2FA | `otplib` in [`routes/2fa.ts`](vscode://file/root/juice-shop/routes/2fa.ts) with rate limiting | ⚠️ Partial — available but optional; rate limit uses `X-Forwarded-For` which is user-controlled |
| **Identity & Access Management** | Session management | In-memory token map `authenticatedUsers.tokenMap` in [`lib/insecurity.ts:72`](vscode://file/root/juice-shop/lib/insecurity.ts:72) | 🔶 Weak — server-side token revocation exists but tokens are also valid if verified independently |
| **Identity & Access Management** | Password hashing | MD5 via `crypto.createHash('md5')` in [`lib/insecurity.ts:43`](vscode://file/root/juice-shop/lib/insecurity.ts:43) | ❌ Missing — MD5 is not a password hashing function; confirmed absent of bcrypt/argon2/scrypt |
| **Authorization** | Role-based access control | Inline role checks (`isAccounting`, `isDeluxe`, `isCustomer`) in [`lib/insecurity.ts:156-175`](vscode://file/root/juice-shop/lib/insecurity.ts:156) | 🔶 Weak — decentralized; inconsistently applied; `PUT /api/Products/:id` auth is commented out |
| **Authorization** | Admin route protection | `security.isAccounting()` on `/rest/order-history/orders` | 🔶 Weak — role check is correct but forged JWTs bypass it entirely |
| **Data Protection** | Transport encryption | No enforced TLS at app layer; depends on deployment proxy | ❌ Missing — application serves HTTP on port 3000 by default; TLS is deployment responsibility not enforced |
| **Data Protection** | Password storage | MD5 hashing (see above) | ❌ Missing — confirmed absent of any modern KDF |
| **Data Protection** | Sensitive data masking | No PII masking or field-level encryption | ❌ Missing — confirmed absent |
| **Secret Management** | RSA private key protection | Hardcoded in source [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23) | ❌ Missing — private key in source code, publicly visible in open source repo |
| **Secret Management** | Cookie secret | Hardcoded `'kekse'` in [`server.ts:289`](vscode://file/root/juice-shop/server.ts:289) | ❌ Missing — trivially known to any reader of the source |
| **Secret Management** | Environment variable usage | `process.env.CTF_KEY`, `process.env.PORT` in [`lib/utils.ts:80`](vscode://file/root/juice-shop/lib/utils.ts:80) | ✅ Adequate — non-sensitive config uses env vars appropriately |
| **Frontend Security** | Angular XSS protection (partial) | Default Angular template binding escapes output | ⚠️ Partial — baseline angular protection exists but is bypassed via `bypassSecurityTrustHtml` in 6+ components |
| **Frontend Security** | `bypassSecurityTrustHtml` misuse | Called in about, administration, search-result, last-login-ip, track-result, data-export components | ❌ Missing — Angular XSS protection intentionally disabled in security-critical display components |
| **Frontend Security** | Content Security Policy | `helmet.xssFilter()` commented out in [`server.ts:187`](vscode://file/root/juice-shop/server.ts:187); no CSP header set | ❌ Missing — confirmed absent via grep |
| **Frontend Security** | Token storage security | JWT stored in `localStorage` in [`Services/request.interceptor.ts:13`](vscode://file/root/juice-shop/frontend/src/app/Services/request.interceptor.ts:13) | ❌ Missing — `localStorage` is XSS-accessible; no `HttpOnly` cookie used |
| **Output Encoding** | Parameterized queries (ORM) | Sequelize ORM used for most models | ⚠️ Partial — ORM used for model operations but raw SQL in `routes/login.ts:34` and `routes/search.ts:23` |
| **Output Encoding** | Raw SQL prevention | Two confirmed raw SQL endpoints | ❌ Missing — raw string interpolation confirmed at login and search |
| **Audit & Logging** | Access logging | Morgan `combined` format to rotating log files in [`server.ts:338`](vscode://file/root/juice-shop/server.ts:338) | ✅ Adequate — HTTP access logging is present and configured |
| **Audit & Logging** | Security event logging | Winston logger used in [`lib/logger.ts`](vscode://file/root/juice-shop/lib/logger.ts) | ⚠️ Partial — logging present but security events (login failure, auth error) not consistently logged |
| **Audit & Logging** | Log access control | Logs browseable at `/support/logs` (unauthenticated) | ❌ Missing — log files publicly accessible |
| **Infrastructure & Network** | Security headers (partial) | `helmet.noSniff()` and `helmet.frameguard()` in [`server.ts:185-186`](vscode://file/root/juice-shop/server.ts:185) | 🔶 Weak — only X-Content-Type-Options and X-Frame-Options set; no HSTS, no CSP, no Referrer-Policy |
| **Infrastructure & Network** | CORS policy | `cors()` with no config (wildcard) in [`server.ts:181-182`](vscode://file/root/juice-shop/server.ts:181) | ❌ Missing — all origins allowed; explicitly documented as intentional ("bludgeon solution") |
| **Infrastructure & Network** | Docker non-root user | `USER 65532` in [`Dockerfile:30`](vscode://file/root/juice-shop/Dockerfile:30) | ✅ Adequate — container runs as non-root UID 65532 |
| **Infrastructure & Network** | Distroless base image | `gcr.io/distroless/nodejs24-debian13` in [`Dockerfile:20`](vscode://file/root/juice-shop/Dockerfile:20) | ✅ Adequate — minimal attack surface; no shell, no package manager |
| **Infrastructure & Network** | Rate limiting | `express-rate-limit` on `/rest/user/reset-password` and 2FA endpoints | 🔶 Weak — rate limit uses `X-Forwarded-For` header which is user-controlled ([`server.ts:346`](vscode://file/root/juice-shop/server.ts:346)); no rate limit on `/rest/user/login` |
| **Dependency & Supply Chain** | Lock files | `package-lock.json` present | ✅ Adequate — lock file present |
| **Dependency & Supply Chain** | SBOM generation | CycloneDX via `npm run sbom` in CI | ✅ Adequate — SBOM generated at build time |
| **Dependency & Supply Chain** | Outdated critical deps | `jsonwebtoken 0.4.0` (latest is 9.x), `express-jwt 0.1.3` (latest is 8.x), `sanitize-html 1.4.2` (latest is 2.x) | ❌ Missing — critically outdated JWT libraries with known CVEs |
| **Security Testing & Pipeline** | SAST | CodeQL (`security-extended` queries) in [`.github/workflows/codeql-analysis.yml`](vscode://file/root/juice-shop/.github/workflows/codeql-analysis.yml) | ✅ Adequate — CodeQL runs on push and PR |
| **Security Testing & Pipeline** | DAST | ZAP baseline scan weekly in [`.github/workflows/zap_scan.yml`](vscode://file/root/juice-shop/.github/workflows/zap_scan.yml) | ✅ Adequate — automated DAST on schedule |

---

## 8. Threat Register

**Risk Distribution:** Critical: 6 · High: 6 · Medium: 5 · Low: 1 · **Total: 18**
**STRIDE Coverage:** Spoofing: 3 · Tampering: 5 · Repudiation: 1 · Information Disclosure: 5 · Denial of Service: 2 · Elevation of Privilege: 2

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | Auth / JWT System | Spoofing | The RSA private key is hardcoded at [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23) and is publicly visible in the open-source repository. Any attacker can extract this key and use `jwt.sign({data:{role:'admin'}}, stolenPrivateKey, {algorithm:'RS256'})` to forge a valid JWT for any user or role, bypassing the entire authentication system. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT RS256 signature is technically correct; in-memory token map provides partial revocation | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | Login Endpoint | Tampering | Raw SQL template literal at [`routes/login.ts:34`](vscode://file/root/juice-shop/routes/login.ts:34) constructs: `SELECT * FROM Users WHERE email = '${req.body.email}'`. An attacker submitting `email: "' OR 1=1--"` retrieves the first database user (typically admin) without knowing any password, achieving authentication bypass. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — no input sanitization, no parameterization | [M-002](#m-002) |
| <a id="t-003"></a>T-003 | Search Endpoint | Information Disclosure | Raw SQL at [`routes/search.ts:23`](vscode://file/root/juice-shop/routes/search.ts:23): `SELECT * FROM Products WHERE name LIKE '%${criteria}%'`. A UNION injection payload (`q=')) UNION SELECT id,email,password,role,'' FROM Users--`) extracts all user credentials including MD5-hashed passwords. MD5 hashes are crackable offline with GPU hardware in seconds for common passwords. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Criteria length capped at 200 chars — insufficient protection | [M-002](#m-002) |
| <a id="t-004"></a>T-004 | User Credential Store | Information Disclosure | Passwords are stored as unsalted MD5 hashes ([`lib/insecurity.ts:43`](vscode://file/root/juice-shop/lib/insecurity.ts:43)). MD5 is not a password hashing function; it has no work factor and produces identical hashes for identical inputs, enabling rainbow table attacks. Once the database is extracted (via T-003), all common passwords can be reversed within minutes using precomputed tables. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — no salt, no modern KDF | [M-003](#m-003) |
| <a id="t-005"></a>T-005 | Product Reviews | Tampering | The `PATCH /rest/products/reviews` endpoint at [`routes/updateProductReviews.ts:18`](vscode://file/root/juice-shop/routes/updateProductReviews.ts:18) uses `{ _id: req.body.id }` as a MarsDB query filter with `{multi: true}`. An attacker can pass a NoSQL operator object (`{"_id": {"$gt": ""}}`) to update all reviews simultaneously, or pass another user's review ID to forge reviews. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT authentication required | [M-004](#m-004) |
| <a id="t-006"></a>T-006 | Auth / Password Management | Spoofing | The password reset endpoint (`POST /rest/user/reset-password`) uses security questions with rate limiting ([`server.ts:343-347`](vscode://file/root/juice-shop/server.ts:343)). However, the rate limit key uses `X-Forwarded-For` header: an attacker can rotate this header to bypass the 100-request limit and brute-force security answers. Additionally, `GET /rest/user/change-password` accepts `current` password in URL query string, exposing it in server logs. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Rate limiter exists but is bypassable via header spoofing | [M-005](#m-005) |
| <a id="t-007"></a>T-007 | Feedback / XSS | Tampering | The `POST /api/Feedbacks` endpoint requires no authentication and stores user-supplied HTML. The Angular frontend renders feedback using `sanitizer.bypassSecurityTrustHtml(feedback.comment)` in [`about.component.ts:119`](vscode://file/root/juice-shop/frontend/src/app/about/about.component.ts:119) and [`administration.component.ts:78`](vscode://file/root/juice-shop/frontend/src/app/administration/administration.component.ts:78). Any visitor or unauthenticated attacker can inject persistent XSS payloads that execute in every user's browser including admin sessions, enabling token theft via `localStorage.getItem('token')`. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | `sanitize-html 1.4.2` partially applied (outdated, bypassable) | [M-006](#m-006) |
| <a id="t-008"></a>T-008 | Angular SPA / Token Storage | Information Disclosure | JWT access tokens are stored in `localStorage` ([`Services/request.interceptor.ts:13`](vscode://file/root/juice-shop/frontend/src/app/Services/request.interceptor.ts:13)). `localStorage` is accessible to any JavaScript running on the same origin. Combined with the XSS vulnerabilities (T-007), an attacker who achieves XSS execution can call `localStorage.getItem('token')` to steal the victim's session token and use it from any location without the victim's knowledge. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None — token deliberately stored in localStorage | [M-007](#m-007) |
| <a id="t-009"></a>T-009 | Product API / Authorization | Elevation of Privilege | The `PUT /api/Products/:id` route has its authorization middleware intentionally commented out at [`server.ts:369`](vscode://file/root/juice-shop/server.ts:369) (`// app.put('/api/Products/:id', security.isAuthorized())`). Any unauthenticated user can send `PUT /api/Products/1` with a modified `price` or `description` to alter product data in the SQLite database. Additionally, `POST /api/Users` allows specifying the `role` field, potentially enabling self-registration as `admin`. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | finale-rest CRUD layer provides some structure; `role` validation in UserModel | [M-008](#m-008) |
| <a id="t-010"></a>T-010 | Static File Endpoints | Information Disclosure | The following paths are served with directory listing and no authentication: `/ftp/` (contains `acquisitions.md`, `incident-support.kdbx`, `coupons_2013.md.bak`); `/encryptionkeys/` (serves `jwt.pub` and `premium.key`); `/support/logs` (full HTTP access logs); `/api-docs` (Swagger UI with complete API spec); `/metrics` (Prometheus internal metrics). Each exposes sensitive operational and cryptographic material. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | robots.txt disallows `/ftp` (not enforced) | [M-009](#m-009) |
| <a id="t-011"></a>T-011 | Log System | Repudiation | HTTP access logs at `/support/logs` are publicly readable by any user ([`server.ts:281`](vscode://file/root/juice-shop/server.ts:281)). These logs contain IP addresses, user agents, and URL patterns of all application users. An attacker can read logs to identify active user sessions and correlate attacker activity, then delete log entries or conduct attacks from behind log-cleaning proxies to evade detection. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Morgan access logging is present | [M-009](#m-009) |
| <a id="t-012"></a>T-012 | Profile Image URL Upload | Information Disclosure | The `POST /profile/image/url` endpoint at [`routes/profileImageUrlUpload.ts:24`](vscode://file/root/juice-shop/routes/profileImageUrlUpload.ts:24) performs a server-side `fetch(url)` with no URL allowlist or scheme restriction. An authenticated attacker can supply an internal URL (`http://169.254.169.254/`, `http://localhost:8080/admin`) to probe internal services. The response body is piped to a file if successful, enabling exfiltration of internal service responses. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | JWT authentication required; error handling partially limits response | [M-010](#m-010) |
| <a id="t-013"></a>T-013 | CORS / Open Redirect | Tampering | CORS is configured with wildcard (`cors()` with no options, [`server.ts:181`](vscode://file/root/juice-shop/server.ts:181)) allowing any origin. The redirect endpoint uses `url.includes(allowedUrl)` at [`lib/insecurity.ts:138`](vscode://file/root/juice-shop/lib/insecurity.ts:138) — a substring match rather than strict equality, allowing `https://github.com/juice-shop/juice-shop.evil.com` to pass validation. An attacker can combine CORS bypass with the open redirect to exfiltrate tokens from cross-site contexts. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Allowlist exists but uses substring matching | [M-011](#m-011) |
| <a id="t-014"></a>T-014 | File Upload — XXE | Information Disclosure | The XML upload handler at [`routes/fileUpload.ts:83`](vscode://file/root/juice-shop/routes/fileUpload.ts:83) parses uploaded XML using `libxmljs2.parseXml(data, {noent: true, nocdata: true})`. The `noent: true` flag enables external entity expansion (XXE). An attacker can submit an XML file with an XXE payload referencing `/etc/passwd` or internal network resources. The parsed content is included in the error response body, directly disclosing the file contents. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None — XXE deliberately enabled | [M-012](#m-012) |
| <a id="t-015"></a>T-015 | File Upload — DoS | Denial of Service | The YAML upload handler at [`routes/fileUpload.ts:117`](vscode://file/root/juice-shop/routes/fileUpload.ts:117) uses `js-yaml.load()` in a vm sandbox. A YAML bomb (billion laughs attack) with deeply nested anchors can exhaust server memory or CPU. The upload size limit is 200KB (`multer limits: {fileSize: 200000}`), but a YAML bomb can expand exponentially within that limit. ZIP uploads also extract without path validation, potentially enabling symlink attacks. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | 200KB size limit; 2-second VM timeout; file type checks | [M-013](#m-013) |
| <a id="t-016"></a>T-016 | B2B Order Endpoint | Denial of Service | The `POST /b2b/v2/orders` endpoint at [`routes/b2bOrder.ts:23`](vscode://file/root/juice-shop/routes/b2bOrder.ts:23) evaluates `orderLinesData` using `vm.runInContext('safeEval(orderLinesData)', sandbox, {timeout: 2000})`. Any authenticated user (any role) can submit an infinite loop payload to cause the 2-second timeout, blocking the worker thread. Sustained requests from multiple authenticated sessions can exhaust Node.js event loop capacity, causing application-wide degradation. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | 2-second timeout configured; JWT auth required | [M-014](#m-014) |
| <a id="t-017"></a>T-017 | Outdated Dependencies | Tampering | `jsonwebtoken 0.4.0` (current: 9.x) and `express-jwt 0.1.3` (current: 8.x) are severely outdated and contain known security vulnerabilities. `sanitize-html 1.4.2` (current: 2.x) is also outdated and may be bypassable with known XSS payloads. These libraries are used on critical security-sensitive code paths. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | SBOM generated; CodeQL SAST runs | [M-015](#m-015) |
| <a id="t-018"></a>T-018 | Application Information Disclosure | Information Disclosure | The endpoints `GET /rest/admin/application-version` and `GET /rest/admin/application-configuration` are accessible without authentication. They expose exact software version numbers and full application configuration including domain names, feature flags, and integration details. The `X-Recruiting` header is set on every response, disclosing information. Error handler in production mode may expose stack traces. | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | `x-powered-by` header disabled | [M-009](#m-009) |

---

## 9. Critical Findings

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-001 — Hardcoded RSA Private Key Enables Arbitrary JWT Forgery

**Scenario:** Any person with read access to the source repository or the running application's process memory can extract the RSA-2048 private key hardcoded at [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23) and use it to sign arbitrary JWT payloads with `algorithm: RS256`. The attacker can set `role: 'admin'` and forge a token accepted by all protected endpoints — bypassing the entire authentication system.

**Current state:** Private key is embedded as a multi-line string literal in the source file at line 23. The public key is separately stored in `encryptionkeys/jwt.pub` and also served unauthenticated at `GET /encryptionkeys/jwt.pub`. No runtime key rotation, no vault integration.

→ **Mitigation:** [M-001 — Externalize and rotate JWT signing key](#m-001)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-002 — SQL Injection in Login Endpoint Enables Authentication Bypass

**Scenario:** The login endpoint builds its SQL query via template literal at [`routes/login.ts:34`](vscode://file/root/juice-shop/routes/login.ts:34). An attacker submitting `{"email": "' OR 1=1--", "password": "x"}` causes the database to return the first user row (admin), issuing a valid admin JWT without any credential. The attacker gains full administrative access.

**Current state:** No parameterization, no ORM usage, no input validation. The `models.sequelize.query()` call uses direct string interpolation.

→ **Mitigation:** [M-002 — Replace raw SQL with parameterized queries](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-003 — SQL Injection in Search Enables Full Database Exfiltration

**Scenario:** The search endpoint at [`routes/search.ts:23`](vscode://file/root/juice-shop/routes/search.ts:23) interpolates `req.query.q` directly into a `LIKE` clause. A UNION injection extracts all rows from the Users table including email addresses and MD5-hashed passwords, which can then be cracked offline using rainbow tables or GPU-based hash cracking.

**Current state:** Only a 200-character length cap is applied — insufficient to prevent multi-step blind injection or UNION extraction within the cap.

→ **Mitigation:** [M-002 — Replace raw SQL with parameterized queries](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-004 — MD5 Password Hashing with No Salt

**Scenario:** All user passwords are hashed with `crypto.createHash('md5')` ([`lib/insecurity.ts:43`](vscode://file/root/juice-shop/lib/insecurity.ts:43)) with no salt. Once database credentials are extracted (T-003), an offline attacker with access to common precomputed MD5 rainbow tables can recover plaintext passwords for the majority of users in seconds. Password reuse across systems amplifies the impact to external accounts.

**Current state:** No bcrypt, argon2, scrypt, or PBKDF2 usage found anywhere in the codebase.

→ **Mitigation:** [M-003 — Replace MD5 with a modern password KDF](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-005 — NoSQL Injection in Product Reviews Allows Mass Review Tampering

**Scenario:** The `PATCH /rest/products/reviews` endpoint passes `req.body.id` directly as a MarsDB filter (`{_id: req.body.id}`) at [`routes/updateProductReviews.ts:18`](vscode://file/root/juice-shop/routes/updateProductReviews.ts:18) with `{multi: true}`. An attacker can pass `{"id": {"$gt": ""}}` to match and overwrite all reviews in the collection simultaneously. Additionally, the `author` field is not re-verified against the requesting user, enabling any authenticated user to modify any other user's review.

**Current state:** JWT authentication is required. No input type validation or query operator filtering.

→ **Mitigation:** [M-004 — Sanitize NoSQL query inputs and enforce ownership checks](#m-004)

---

### <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> T-007 — Persisted XSS via Unauthenticated Feedback + Angular Sanitization Bypass

**Scenario:** An unauthenticated attacker submits feedback with an HTML/JavaScript payload to `POST /api/Feedbacks`. The Angular frontend renders it in the About page and Admin panel using `sanitizer.bypassSecurityTrustHtml()` at [`about.component.ts:119`](vscode://file/root/juice-shop/frontend/src/app/about/about.component.ts:119). The script executes in every visitor's browser including admin sessions, and can call `localStorage.getItem('token')` to exfiltrate the JWT to an attacker-controlled endpoint.

**Current state:** `sanitize-html 1.4.2` is applied server-side (outdated version with known bypasses). Angular XSS protection is explicitly disabled at the rendering layer.

→ **Mitigation:** [M-006 — Fix XSS in feedback rendering pipeline](#m-006)

---

## 10. Mitigation Register

### <a id="m-001"></a>M-001 · Externalize and Rotate JWT Signing Key

**Addresses:** [T-001](#t-001)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** The hardcoded private key means the authentication system provides no security — any attacker with source access can forge any identity. This is a complete authentication bypass.

**How:**
1. Remove the hardcoded private key from `lib/insecurity.ts:23`
2. Generate a new RSA-2048 key pair (or switch to EdDSA with Ed25519 for better performance)
3. Load the private key from an environment variable or a secrets manager (e.g., `process.env.JWT_PRIVATE_KEY`)
4. Store the public key in an environment variable or at a non-publicly-served path
5. Rotate both keys immediately as the old key should be considered compromised

```typescript
// BEFORE (lib/insecurity.ts:23) - NEVER DO THIS:
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXA...'

// AFTER - load from environment or secrets manager:
const privateKey = process.env.JWT_PRIVATE_KEY
  ?? fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH ?? '/run/secrets/jwt-private-key', 'utf8')
if (!privateKey) throw new Error('JWT_PRIVATE_KEY environment variable is required')
```

**Reference:** [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), CWE-321

---

### <a id="m-002"></a>M-002 · Replace Raw SQL with Parameterized Queries

**Addresses:** [T-002](#t-002), [T-003](#t-003)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** Raw SQL string interpolation is the direct cause of the SQL injection vulnerabilities in login and search. Parameterized queries eliminate the attack vector entirely.

**How:**
1. Replace `routes/login.ts:34` string interpolation with Sequelize `findOne` using a `where` clause
2. Replace `routes/search.ts:23` with a Sequelize `Op.like` parameterized query
3. Never use `sequelize.query()` with user input; use Sequelize model methods or bind parameters

```typescript
// BEFORE (routes/login.ts:34) - SQLi vulnerable:
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' ...`)

// AFTER - parameterized via Sequelize:
UserModel.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password),
    deletedAt: null
  }
})

// BEFORE (routes/search.ts:23) - SQLi vulnerable:
models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'...`)

// AFTER - parameterized:
ProductModel.findAll({
  where: {
    [Op.or]: [
      { name: { [Op.like]: `%${criteria}%` } },
      { description: { [Op.like]: `%${criteria}%` } }
    ],
    deletedAt: null
  }
})
```

**Reference:** [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), CWE-89

---

### <a id="m-003"></a>M-003 · Replace MD5 with a Modern Password KDF

**Addresses:** [T-004](#t-004)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** MD5 is a general-purpose hash with no work factor. An attacker who extracts the database can crack all user passwords within minutes using GPU hardware and precomputed tables.

**How:**
1. Install `bcrypt` or `argon2` (Argon2id preferred per OWASP): `npm install argon2`
2. Replace `security.hash()` function in `lib/insecurity.ts:43` with an async Argon2id hash
3. Update `login.ts` to use `argon2.verify()` for comparison (async)
4. Plan a migration path: hash existing MD5 values with Argon2 on next successful login (re-hashing on login)

```typescript
// BEFORE (lib/insecurity.ts:43):
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// AFTER:
import argon2 from 'argon2'
export const hash = async (data: string): Promise<string> =>
  argon2.hash(data, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 })
export const verifyHash = async (data: string, stored: string): Promise<boolean> =>
  argon2.verify(stored, data)
```

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), CWE-916

---

### <a id="m-004"></a>M-004 · Sanitize NoSQL Query Inputs and Enforce Ownership Checks

**Addresses:** [T-005](#t-005)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** Passing raw user input as a MarsDB query selector allows injection of query operators, enabling mass updates. The absence of author verification allows review forgery.

**How:**
1. Validate that `req.body.id` is a string (not an object) before using it as a query filter
2. Pass the string ID directly; MarsDB will not treat a plain string as an operator
3. Add an ownership check: verify that the review's `author` matches the requesting user's email
4. Remove `{multi: true}` unless a genuine multi-update use case exists

```typescript
// BEFORE (routes/updateProductReviews.ts:18):
db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } },
  { multi: true }  // Dangerous: matches all if _id is operator
)

// AFTER:
const id = req.body.id
if (typeof id !== 'string') return res.status(400).json({ error: 'Invalid id' })
const user = security.authenticatedUsers.from(req)
// Verify ownership before update
const existing = await db.reviewsCollection.findOne({ _id: id })
if (!existing || existing.author !== user?.data?.email) {
  return res.status(403).json({ error: 'Forbidden' })
}
db.reviewsCollection.update({ _id: id }, { $set: { message: req.body.message } })
```

**Reference:** [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html), CWE-943

---

### <a id="m-005"></a>M-005 · Fix Rate Limit Bypass and Password-in-URL Exposure

**Addresses:** [T-006](#t-006)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** The rate limiter on password reset trusts the `X-Forwarded-For` header set by the client, allowing any attacker to bypass it. Sending the current password as a URL query parameter exposes it in server access logs and browser history.

**How:**
1. Fix `server.ts:346` — do not use `X-Forwarded-For` as the rate limit key unless a trusted proxy is configured; use `ip` directly or configure `trustProxy` only when a known reverse proxy is present
2. Change `GET /rest/user/change-password` to `POST` and move credentials to the request body
3. Ensure `morgan` logging does not log request bodies containing passwords

```typescript
// BEFORE (server.ts:343-347):
app.use('/rest/user/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip } // User-controlled!
}))

// AFTER:
app.use('/rest/user/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,  // Reduce from 100 to 10 for brute-force resistance
  keyGenerator ({ ip }) { return ip }  // Trust only socket IP
}))
```

**Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), CWE-307

---

### <a id="m-006"></a>M-006 · Fix XSS in Feedback Rendering Pipeline

**Addresses:** [T-007](#t-007)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Persisted XSS via unauthenticated feedback submission with Angular's sanitization bypassed allows any anonymous user to inject scripts that execute in admin browsers, enabling token theft and account takeover.

**How:**
1. Remove all `sanitizer.bypassSecurityTrustHtml()` calls in `about.component.ts`, `administration.component.ts`, `search-result.component.ts`, `last-login-ip.component.ts`, and `track-result.component.ts`
2. Use Angular's default safe interpolation (`{{ comment }}`) or use the `[innerText]` binding instead of `[innerHTML]`
3. Update `sanitize-html` to the latest 2.x version if HTML rendering is truly required
4. Add authentication requirement to `POST /api/Feedbacks` endpoint
5. Implement a Content Security Policy header (`script-src 'self'`) via `helmet.contentSecurityPolicy()`

```typescript
// BEFORE (about.component.ts:119):
feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(feedbacks[i].comment)

// AFTER — use safe text binding in template:
// In component: feedbacks[i].comment = feedbacks[i].comment  (plain string)
// In template:  <span>{{ feedback.comment }}</span>  (auto-escaped)
```

**Reference:** [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), CWE-79

---

### <a id="m-007"></a>M-007 · Move JWT from localStorage to HttpOnly Cookie

**Addresses:** [T-008](#t-008)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** High

**Why:** Tokens in `localStorage` are readable by any JavaScript on the page, making XSS attacks immediately escalatable to session hijacking. HttpOnly cookies are inaccessible to JavaScript.

**How:**
1. After successful login, set the JWT as an `HttpOnly; Secure; SameSite=Strict` cookie on the server side
2. Remove `localStorage.setItem('token', ...)` from the Angular login flow
3. Update `request.interceptor.ts` to not manually add the Authorization header — the browser will send the cookie automatically
4. Update server-side JWT extraction to read from the cookie rather than the `Authorization` header
5. Implement CSRF protection (synchronizer token or `SameSite=Strict` cookie) since cookies are automatically sent

```typescript
// AFTER (server-side login response):
res.cookie('auth_token', token, {
  httpOnly: true,   // Inaccessible to JavaScript
  secure: true,     // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 6 * 60 * 60 * 1000  // 6 hours (matches JWT expiry)
})
res.json({ authentication: { bid: basket.id, umail: user.data.email } })
// NOTE: Do not include the token in the JSON body
```

**Reference:** [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), CWE-1004

---

### <a id="m-008"></a>M-008 · Enforce Authorization on Product Update and Registration

**Addresses:** [T-009](#t-009)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Unauthenticated product modification and self-assigning admin roles undermine data integrity and access control entirely.

**How:**
1. Uncomment `app.put('/api/Products/:id', security.isAuthorized())` at `server.ts:369`
2. Add additional admin-role check for product updates (customers should not be able to modify products)
3. Strip the `role` field from user registration body before processing, or validate it cannot be set to a privileged value

```typescript
// AFTER (server.ts:369) — restore and extend:
app.put('/api/Products/:id', security.isAuthorized(), security.isAccounting())

// AFTER (server.ts:407) — strip privileged fields from registration:
app.post('/api/Users', (req, res, next) => {
  delete req.body.role  // Never trust client-supplied role
  delete req.body.isActive
  next()
})
```

**Reference:** [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), CWE-285

---

### <a id="m-009"></a>M-009 · Restrict Unauthenticated Access to Sensitive Endpoints

**Addresses:** [T-010](#t-010), [T-011](#t-011), [T-018](#t-018)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Publicly accessible `/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics`, and `/api-docs` expose cryptographic keys, internal logs, infrastructure metrics, and full API documentation to any attacker.

**How:**
1. Add `security.isAuthorized()` middleware before `/metrics`, `/api-docs`, `/support/logs`, and `/encryptionkeys` routes
2. Remove `serveIndex` for `/encryptionkeys/` entirely — do not serve the directory listing
3. Move sensitive FTP files to a non-publicly-served location or add authentication
4. Add admin-role check for log access and Prometheus metrics
5. Configure `swagger-ui-express` to require authentication or disable in production

```typescript
// AFTER (server.ts):
app.use('/metrics', security.isAuthorized(), security.isAccounting(), metrics.serveMetrics())
app.use('/api-docs', security.isAuthorized(), swaggerUi.serve, swaggerUi.setup(swaggerDocument))
app.use('/support/logs', security.isAuthorized(), security.isAccounting(), ...)
// Remove /encryptionkeys public serving entirely
```

**Reference:** [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/), CWE-200

---

### <a id="m-010"></a>M-010 · Add URL Allowlist to Prevent SSRF in Profile Image Upload

**Addresses:** [T-012](#t-012)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Server-side fetch of arbitrary URLs allows internal network probing, accessing cloud metadata endpoints, and exfiltrating internal service responses.

**How:**
1. Validate the URL scheme — only allow `https://`
2. Validate against an allowlist of trusted image CDNs or domains
3. Block RFC 1918 private addresses and loopback addresses before fetching
4. Use `URL` parsing to extract and validate the hostname before making the request

```typescript
// AFTER (routes/profileImageUrlUpload.ts):
const BLOCKED_HOSTS = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/
const parsed = new URL(url)
if (parsed.protocol !== 'https:') throw new Error('Only HTTPS URLs allowed')
if (BLOCKED_HOSTS.test(parsed.hostname)) throw new Error('Private addresses not allowed')
```

**Reference:** [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), CWE-918

---

### <a id="m-011"></a>M-011 · Fix Open Redirect Allowlist to Use Exact Matching

**Addresses:** [T-013](#t-013)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** The substring-based `url.includes(allowedUrl)` check at `lib/insecurity.ts:138` allows attackers to construct redirect URLs containing an allowlisted string as a subdomain (e.g., `https://github.com/juice-shop/juice-shop.attacker.com`), bypassing the validation.

**How:**
1. Replace `url.includes(allowedUrl)` with exact URL matching using `URL` parsing
2. Compare `parsed.href` against the exact allowlisted values, or compare `parsed.origin` and `parsed.pathname`

```typescript
// BEFORE (lib/insecurity.ts:138):
allowed = allowed || url.includes(allowedUrl) // Substring match - bypassable!

// AFTER - exact origin+path matching:
import { URL } from 'url'
export const isRedirectAllowed = (url: string): boolean => {
  try {
    const parsed = new URL(url)
    for (const allowedUrl of redirectAllowlist) {
      const allowed = new URL(allowedUrl)
      if (parsed.origin === allowed.origin && parsed.pathname === allowed.pathname) return true
    }
    return false
  } catch { return false }
}
```

**Reference:** [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), CWE-601

---

### <a id="m-012"></a>M-012 · Disable XXE in XML Upload Handler

**Addresses:** [T-014](#t-014)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** `noent: true` in `libxmljs2.parseXml()` enables external entity expansion, allowing an attacker to read local files and probe internal services via XXE.

**How:**
1. Change `noent: true` to `noent: false` in `routes/fileUpload.ts:83`
2. Also set `nonet: true` to prevent network-based entity resolution

```typescript
// BEFORE (routes/fileUpload.ts:83):
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', ...)

// AFTER:
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true, nonet: true })', ...)
```

**Reference:** [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), CWE-611

---

### <a id="m-013"></a>M-013 · Harden File Upload Against YAML Bomb and Path Traversal

**Addresses:** [T-015](#t-015)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** YAML bomb payloads can exhaust memory within the 200KB file size limit. ZIP extraction does not fully validate that extracted paths remain within the target directory.

**How:**
1. Use `yaml.load(data, {schema: yaml.FAILSAFE_SCHEMA})` to prevent alias/anchor expansion for YAML uploads
2. For ZIP uploads, verify that `absolutePath` strictly starts with `path.resolve('uploads/complaints/')` (add trailing slash to prevent prefix bypass)
3. Set a maximum extraction size and file count for ZIP archives
4. Consider removing the YAML and ZIP upload features if not required for core functionality

**Reference:** [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), CWE-400

---

### <a id="m-014"></a>M-014 · Restrict B2B Order Endpoint to Admin/Accounting Role

**Addresses:** [T-016](#t-016)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Any authenticated user can cause a 2-second thread block via the `orderLinesData` evaluation. Sustained abuse can degrade the Node.js event loop for all users.

**How:**
1. Add `security.isAccounting()` middleware to `POST /b2b/v2/orders` to restrict to accounting role
2. Validate that `orderLinesData` is a plain string with no operator characters before evaluation
3. Consider removing `vm.runInContext` / `safeEval` entirely if dynamic evaluation is not required

```typescript
// AFTER (server.ts):
app.post('/b2b/v2/orders', security.isAuthorized(), security.isAccounting(), b2bOrder())
```

**Reference:** [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html), CWE-400

---

### <a id="m-015"></a>M-015 · Upgrade Critically Outdated Security Dependencies

**Addresses:** [T-017](#t-017)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** `jsonwebtoken 0.4.0` and `express-jwt 0.1.3` are severely outdated with known CVEs. `sanitize-html 1.4.2` has known bypass techniques. These libraries handle security-critical operations.

**How:**
1. Upgrade `jsonwebtoken` to `^9.0.2` (latest stable): `npm install jsonwebtoken@^9.0.2`
2. Upgrade `express-jwt` to `^8.4.1`: `npm install express-jwt@^8.4.1` — note the API changed significantly; update usage accordingly
3. Upgrade `sanitize-html` to `^2.13.0`
4. Configure `algorithms` option in `express-jwt` to explicitly allowlist only `RS256`
5. Enable Dependabot or Renovate for automated dependency updates

```typescript
// AFTER - with algorithm allowlist (express-jwt v8 API):
import { expressjwt } from 'express-jwt'
export const isAuthorized = () => expressjwt({
  secret: publicKey,
  algorithms: ['RS256'],  // Explicitly reject alg:none and symmetric algorithms
  requestProperty: 'auth'
})
```

**Reference:** [OWASP Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/), CWE-1035

---

## 11. Out of Scope

The following areas were not analyzed in depth for this assessment:

- **Web3/Blockchain components** (`routes/web3Wallet.ts`, `routes/nftMint.ts`): Smart contract interaction and Ethereum wallet security were not assessed. The endpoints were identified as part of the attack surface but blockchain-specific threats (reentrancy, front-running, etc.) are out of scope.
- **Chatbot training data security** (`data/chatbot/`): The juicy-chat-bot training data format and model security were not assessed beyond identifying the SSRF risk in the training data download URL.
- **Kubernetes / cloud-provider-specific deployment** configs: No such configs were found; all Kubernetes network policy and cloud IAM recommendations are deployment-environment-specific.
- **Third-party dependency CVE inventory**: While outdated dependencies were identified, a full CVE-by-CVE enumeration of all vulnerable library versions was not performed — this is better done with a dedicated SCA tool (Snyk, Grype, or the existing CycloneDX SBOM).
- **CTF challenge infrastructure**: The scoring, notification, and progress-tracking systems were analyzed only as part of the broader attack surface.
- **Frontend Angular component security** (all ~50+ components): Only components directly involved in confirmed XSS vectors were reviewed. A full Angular security audit would require analyzing every component for injection, CSRF, and state management risks.
- **Vagrant deployment**: The `vagrant/` directory was not analyzed.
