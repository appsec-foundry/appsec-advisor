# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-05T00:00:00Z |
| Analysis Duration | 18 min 42 s |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Input Tokens | unavailable |
| Output Tokens | unavailable |
| Cache Read Tokens | unavailable |
| Cache Write Tokens | unavailable |
| Estimated Cost | unavailable |
| Context Sources | None |

> ℹ Token and cost data are not accessible at agent runtime. Check the Anthropic Console for usage details of this session.

---

## Contents

- [1. System Overview](#1-system-overview)
- [2. Architecture Diagrams](#2-architecture-diagrams)
  - [2.1 System Context](#21-system-context-level-0)
  - [2.2 Containers](#22-containers-level-1)
  - [2.4 Technology Architecture](#24-technology-architecture-annotated)
  - [2.5 Security Architecture Assessment](#25-security-architecture-assessment)
- [3. Security-Relevant Use Cases](#3-security-relevant-use-cases)
  - [3.1 Authentication Flow](#31-authentication-flow)
  - [3.2 Authorization / Access Control](#32-authorization--access-control)
  - [3.3 File Upload Flow](#33-file-upload-flow)
  - [3.4 OAuth / Google Login Flow](#34-oauth--google-login-flow)
  - [3.5 Password Reset Flow](#35-password-reset-flow)
  - [3.6 Input Validation and SQL Injection Surface](#36-input-validation-and-sql-injection-surface)
- [4. Assets](#4-assets)
- [5. Attack Surface](#5-attack-surface)
- [6. Trust Boundaries](#6-trust-boundaries)
- [7. Identified Security Controls](#7-identified-security-controls)
- [8. Threat Register](#8-threat-register)
- [9. Critical Findings](#9-critical-findings)
- [10. Mitigation Register](#10-mitigation-register)
- [11. Out of Scope](#11-out-of-scope)

---

## 1. System Overview

OWASP Juice Shop is the world's most sophisticated and modern **intentionally vulnerable** web application. It is used for security training, penetration testing practice, CTF competitions, and as a validation target for security tooling. The application is maintained by Bjoern Kimminich and the OWASP community and is a Flagship OWASP Project at version 19.2.1.

**Architecture complexity tier: Moderate.** The system consists of two distinct deployable layers — an Angular 17 SPA served as static files and a Node.js/Express REST API backend — sharing a single process boundary. The SQLite database is file-based and co-located with the server process. This warrants a Context diagram and Container-level diagram.

**Repository:** https://github.com/juice-shop/juice-shop
**Team:** OWASP Juice Shop Community / Bjoern Kimminich
**Compliance scope:** OWASP Top 10 (intentionally non-compliant for educational purposes)
**Asset classification:** Tier 2 / Educational

> ℹ No external context sources were available for this assessment.

**Business context:** Juice Shop deliberately implements every OWASP Top 10 vulnerability category and many additional flaws as hacking "challenges." It is designed to be run in controlled training environments, not in production. The application seeded with sample user data, products, and orders — no real PII or financial data is processed.

**Overall security impression:** This application has the most severe security posture of any analyzed codebase — by design. Every major vulnerability class is intentionally present and exploitable: SQL injection, XSS (stored and reflected), Server-Side Template Injection, Remote Code Execution via `eval()`, SSRF, XXE, path traversal, hardcoded secrets, broken authentication, JWT algorithm confusion, deprecated OAuth flows, missing CSRF protection, wildcard CORS, and exposed sensitive endpoints. From a threat modeling perspective, this is an ideal case study in what not to do. The threat model below catalogs these findings in structured STRIDE format to serve as an educational reference.

---

## 2. Architecture Diagrams

### 2.1 System Context (Level 0)

```mermaid
graph TD

classDef person   fill:#08427B,stroke:#073B6F,color:#fff
classDef system   fill:#1168BD,stroke:#0E5CA8,color:#fff
classDef external fill:#999,stroke:#666,color:#fff
classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

subgraph INTERNET["🌐 Public Internet · untrusted"]
  USER(["👤 Trainee / Security Student\nBrowser-based user"]):::person
  ATTACKER(["👤 Attacker / CTF Player\nBrowser-based adversary"]):::person
  GOOGLE["Google OAuth\naccounts.google.com\nExternal Identity Provider"]:::external
end

subgraph INTERNAL["🔒 Hosted Environment · single container"]
  JUICESHOP["OWASP Juice Shop\nv19.2.1 · Intentionally Vulnerable\nNode.js 24 + Angular 17\nDocker · port 3000"]:::risk
end

USER      -->|"HTTP/HTTPS · GET / (browse shop)"| JUICESHOP
ATTACKER  -->|"HTTP/HTTPS · exploit challenges"| JUICESHOP
JUICESHOP -->|"HTTPS · OAuth implicit flow\nresponse_type=token (deprecated)"| GOOGLE

%% Trust Boundary Key:
%% 🌐 Public Internet → 🔒 Internal: No WAF, no API gateway — direct HTTP to Node.js
```

*Caption: Users and attackers interact directly with the Juice Shop instance. Google OAuth is the only external integration. No WAF, CDN, or API gateway sits in front of the application.*

### 2.2 Containers (Level 1)

```mermaid
graph TD

classDef container fill:#1168BD,stroke:#0E5CA8,color:#fff
classDef db        fill:#2E7D32,stroke:#1B5E20,color:#fff
classDef external  fill:#999,stroke:#666,color:#fff
classDef risk      fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

subgraph INTERNET["🌐 Public Internet · untrusted"]
  USER(["👤 User / Attacker"])
end

subgraph APP_CONTAINER["🔒 Application Container · Docker distroless node:24"]
  SPA["Angular 17 SPA\nServed as static files\nby Express · port 3000"]:::risk
  API["Express REST API\nNode.js 24 · TypeScript\nJWT RS256 auth · port 3000"]:::risk
  UPLOADS["File Storage\nLocal filesystem\nftp/ uploads/ logs/"]:::risk
end

subgraph DATA_TIER["🔐 Data Tier · embedded in container"]
  SQLITE[("SQLite DB\ndata/juiceshop.sqlite\nSequelize ORM")]:::db
  MARSDB[("MarsDB (MongoDB-like)\nIn-memory + file\nOrders + Reviews")]:::db
end

USER   -->|"HTTPS · GET / (static SPA assets)"| SPA
USER   -->|"HTTPS · REST API calls"| API
SPA    -->|"HTTPS · JSON API requests"| API
API    -->|"SQL · file-based (Sequelize)"| SQLITE
API    -->|"MarsDB queries"| MARSDB
API    -->|"filesystem read/write"| UPLOADS

%% Trust Boundary Key:
%% 🌐 Public Internet → 🔒 App Container: No ingress filtering — raw HTTP/HTTPS to Express
%% 🔒 App Container → 🔐 Data Tier: Same process — SQLite file in container, no network isolation
```

*Caption: The SPA and REST API share the same Express process. SQLite and MarsDB are embedded in the container. There is no network boundary between application and data tiers.*

### 2.4 Technology Architecture (Annotated)

```mermaid
graph TB

classDef core     fill:#1E90FF,stroke:#333,color:#000,stroke-width:2px
classDef db       fill:#9ACD32,stroke:#333,color:#000,stroke-width:2px
classDef external fill:#FFD700,stroke:#333,color:#000,stroke-width:2px
classDef risk     fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

User(("👤 User / Attacker"))

subgraph FE_LAYER["Frontend · Docker distroless node:24 (served by Express)"]
  FE["Angular SPA\nAngular 17 + Angular Material\nTypeScript · Node 24 build\nDocker container port 3000"]:::risk
end

subgraph BE_LAYER["Backend · Docker distroless node:24"]
  BE["REST API\nExpress 4.x + TypeScript\nNode.js 24\nJWT RS256 (hardcoded key!)"]:::risk
  AUTH["Auth Module\nlib/insecurity.ts\njsonwebtoken 0.4.0\nexpress-jwt 0.1.3 (outdated!)"]:::risk
end

subgraph DB_LAYER["Database · embedded in container"]
  SQLITE[("User/Product DB\nSQLite 5.x\nSequelize ORM 6.x\ndata/juiceshop.sqlite")]:::db
  MARSDB[("Orders/Reviews\nMarsDB 0.6.x\nIn-memory + file\ndata/mongodb/")]:::db
end

subgraph INFRA_LAYER["Infrastructure and CI/CD · GitHub Actions"]
  CICD["CI/CD Pipeline\nGitHub Actions\nCodeQL SAST\nOWASP ZAP DAST"]:::external
end

User   -->|"HTTP · port 3000 (no TLS by default)"| FE
FE     -->|"REST API calls · JSON"| BE
BE     -->|"SQL · raw concatenation (SQLi!)"| SQLITE
BE     -->|"MarsDB queries"| MARSDB
CICD   -.->|"builds and tests"| BE
AUTH   -.->|"signs JWT tokens"| BE
```

*Caption: Technology stack. Pink nodes carry identified threats. The auth module uses outdated JWT libraries with a hardcoded private key. SQLite is accessed both via ORM and raw SQL concatenation.*

### 2.5 Security Architecture Assessment

#### Architecture Patterns

| Pattern | Present | Notes |
|---------|---------|-------|
| API Gateway / edge enforcement (centralized auth, rate limiting, WAF) | ❌ | No API gateway. Express handles everything directly. Rate limiting applied only to select endpoints (`/rest/user/reset-password`, `/rest/2fa/*`), not globally. |
| Backend for Frontend (BFF) for SPA token handling | ❌ | SPA calls the API directly with Bearer tokens stored in `localStorage`. No BFF pattern. Tokens are exposed to JavaScript. |
| Defense-in-depth (multiple independent layers before sensitive data) | ❌ | Single Express process handles auth, business logic, and data access. No independent layers. |
| Separation of concerns (auth logic isolated from business logic) | ⚠️ | `lib/insecurity.ts` centralizes JWT utilities, but auth middleware is applied inconsistently — some routes unprotected (e.g., `PUT /api/Products/:id` commented out at [server.ts:369](vscode://file/root/juice-shop/server.ts:369)). |
| Least-privilege service accounts and inter-service identity | ❌ | SQLite accessed with embedded credentials. No service accounts or IAM. |
| Secrets management (no hardcoded secrets, external vault/manager) | ❌ | RSA private key hardcoded at [lib/insecurity.ts:23](vscode://file/root/juice-shop/lib/insecurity.ts:23). HMAC secret hardcoded at line 44. Cookie secret hardcoded at [server.ts:289](vscode://file/root/juice-shop/server.ts:289). |
| Network segmentation (public / DMZ / internal / data tier) | ❌ | No network segmentation. All tiers run in a single Docker container with no port isolation. |
| Secure defaults (fail-closed auth, deny-by-default ACL) | ⚠️ | Some routes use `security.denyAll()` explicitly, but access control is additive/opt-in rather than deny-by-default. CORS is wildcard. `xssFilter` is explicitly disabled. |

#### Trust Model Evaluation

The trust model is fundamentally broken for a production application (though intentional for training):

- **No boundary enforcement between public internet and application:** Users connect directly to the Express server on port 3000 with no WAF, CDN, or reverse proxy. Any attacker can reach all endpoints directly.
- **No boundary between application and data tiers:** SQLite runs as a file embedded in the same container process as the Express server. A successful RCE in the Express layer grants direct file-system access to the database.
- **Fail-open authentication:** The `isAuthorized()` middleware uses `expressJwt` which rejects invalid tokens, but several routes are completely unprotected (e.g., product update at `/api/Products/:id`, metrics at `/metrics`). The system is fail-open by design.
- **Implicit trust in JWT claims:** Role elevation is based on `role` claim in JWT payload decoded client-side (`app.guard.ts`) and server-side via `lib/insecurity.ts`. Since the private key is public, anyone can forge a JWT with `role: admin`.

#### Authentication and Authorization Architecture

- **Auth enforcement:** Partially centralized via `security.isAuthorized()` middleware, but applied inconsistently per-route in `server.ts`. This is distributed (opt-in) rather than centralized.
- **Token strategy:** Stateless JWT (RS256), but the private key is publicly visible in source code. Token validity is 6 hours. Tokens stored in `localStorage` (accessible to XSS).
- **OAuth/OIDC:** Google OAuth using **implicit flow** (`response_type=token`) at [login.component.ts:134](vscode://file/root/juice-shop/frontend/src/app/login/login.component.ts:134) — this is **deprecated** per RFC 9700. No PKCE, no `state` parameter validation.
- **Privilege model:** Role-based (customer, deluxe, accounting, admin) checked via JWT claim. Angular route guards are client-side only and bypassable.
- **Admin access:** Uses same authentication as regular users — only the `role` claim differs. A forged JWT with `role: admin` bypasses all restrictions.

#### Key Architectural Risks

| # | Structural Risk | Impact if exploited | Linked threats |
|---|----------------|---------------------|---------------|
| 1 | Hardcoded RSA private key in source code — any actor with code access can forge admin-level JWTs | Full authentication bypass, complete account takeover for any user | T-001 |
| 2 | Token storage in `localStorage` — XSS leads to direct token theft | Any XSS vulnerability becomes an authentication bypass, not just page defacement | T-002, T-010 |
| 3 | No API gateway or centralized WAF — SQL injection, XSS, and injection payloads reach application code unfiltered | SQLi, XSS, XXE, SSTI, RCE via a single HTTP request | T-003, T-004, T-005, T-006 |
| 4 | Single-container deployment without network segmentation — application and database share filesystem | RCE in Express layer gives immediate database access, no lateral movement needed | T-007 |
| 5 | Deprecated OAuth implicit flow — access token exposed in URL fragment, browser history, and Referer headers | Token theft via network sniffing, browser history, referrer leakage | T-008 |

#### Overall Architecture Security Rating

**Rating: 🔴 Critical gaps**

> Justification: Every foundational security architecture pattern is absent or critically broken — no secret management (hardcoded RSA key), no network segmentation, no secure token storage, deprecated authentication flows, wildcard CORS, and multiple unprotected endpoints including a full Prometheus metrics exposure. While these are intentional for training, the structural weaknesses are real and would result in complete compromise of any production deployment within minutes. The combination of a publicly known RSA private key and JWT-based authentication means authentication as any user (including admin) requires only a single crafted HTTP request.

---

## 3. Security-Relevant Use Cases

### 3.1 Authentication Flow

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant SPA as Angular SPA
    participant API as Express API
    participant DB as SQLite DB

    U->>SPA: Enter email + password on /login
    SPA->>API: POST /rest/user/login {email, password}
    Note over API: NO rate limiting on login endpoint
    API->>DB: SELECT * FROM Users WHERE email='${email}' AND password='${md5(password)}'
    Note over DB: RAW SQL CONCATENATION - SQL Injection possible!
    Note over DB: Password hashed with MD5 (weak hash)
    DB-->>API: User row (or null)
    alt User has TOTP enabled
        API-->>SPA: 401 {status: 'totp_token_required', tmpToken: JWT}
        SPA->>U: Show 2FA prompt
        U->>SPA: Enter TOTP code
        SPA->>API: POST /rest/2fa/verify {tmpToken, totpToken}
        Note over API: Rate limited: 100 req/5min window
        API-->>SPA: 200 {token: JWT, bid, umail}
    else No TOTP
        API->>API: security.authorize(user) - signs JWT with hardcoded privateKey
        API->>API: authenticatedUsers.put(token, user) - in-memory map
        API-->>SPA: 200 {token: JWT, bid: basketId, umail}
    end
    SPA->>SPA: localStorage.setItem('token', jwt)
    Note over SPA: TOKEN STORED IN localStorage - XSS risk!
    SPA->>SPA: Cookie also set via cookieService
    U-->>SPA: Authenticated session established
```

*The login endpoint uses raw SQL string concatenation making it trivially injectable. Passwords are hashed with MD5 (not bcrypt/argon2). The resulting JWT is stored in `localStorage` exposing it to any XSS. There is no rate limiting on the primary login endpoint (`POST /rest/user/login`). The JWT private key is hardcoded in source, allowing anyone to forge tokens.*

### 3.2 Authorization / Access Control

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant SPA as Angular SPA (Guard)
    participant MW as Express Middleware
    participant API as Route Handler
    participant DB as SQLite

    Note over SPA: Client-side guard (bypassable!)
    U->>SPA: Navigate to /administration
    SPA->>SPA: AdminGuard.canActivate()
    SPA->>SPA: jwtDecode(localStorage.token).data.role === 'admin'?
    Note over SPA: Client-side only check - easily bypassed

    alt Admin role in JWT
        SPA-->>U: Show admin page
        U->>API: GET /api/Users (with Bearer token)
        API->>MW: security.isAuthorized() - expressJwt verifies token
        Note over MW: Verifies signature using PUBLIC key
        Note over MW: Private key is hardcoded - anyone can forge admin JWT!
        MW->>API: next() - authorized
        API->>DB: SELECT * FROM Users (all users exposed)
        DB-->>API: All user records
        API-->>U: 200 User list (emails, roles, etc)
    else Non-admin role
        SPA->>SPA: forbidRoute() - redirect to /403
        Note over SPA: But direct API call with forged admin JWT still works!
    end

    Note over API: PUT /api/Products/:id has NO auth middleware
    U->>API: PUT /api/Products/:id {price: 0}
    Note over API: Line 369 server.ts - auth middleware commented out!
    API->>DB: UPDATE Products SET price=0
    DB-->>API: Success
    API-->>U: 200 - Product modified without auth!
```

*Authorization is partly client-side (Angular guards) and partly server-side (JWT middleware). The client-side guards are completely bypassable. Server-side JWT validation is present but inconsistently applied — `PUT /api/Products/:id` has no middleware. Roles are encoded in JWT claims that can be forged due to the hardcoded private key.*

### 3.3 File Upload Flow

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant API as Express API
    participant FS as Filesystem

    Note over U: ZIP File Upload (Path Traversal)
    U->>API: POST /file-upload (multipart ZIP file)
    API->>API: ensureFileIsPassed() - file present?
    API->>API: checkUploadSize() - > 100KB?
    API->>API: checkFileType() - extension check only
    API->>API: handleZipFileUpload()
    API->>FS: unzipper.Parse() entries
    Note over FS: Path traversal check: absolutePath.includes(path.resolve('.'))
    Note over FS: Insufficient check - ZIP slip to ftp/legal.md!
    FS->>FS: Write entry to uploads/complaints/{fileName}

    Note over U: XML File Upload (XXE)
    U->>API: POST /file-upload (multipart XML file)
    API->>API: handleXmlUpload()
    API->>API: libxml.parseXml(data, {noent: true})
    Note over API: noent:true enables external entity expansion!
    Note over API: XXE file disclosure - reads /etc/passwd etc.
    API-->>U: 410 Error with XML content in message (data leak!)

    Note over U: Profile Image URL (SSRF)
    U->>API: POST /profile/image/url {imageUrl: 'http://internal/...'}
    API->>API: fetch(url) - NO URL validation!
    Note over API: Server-side fetch to attacker-controlled URL
    API->>FS: Write fetched content to uploads/{userId}.ext
    API-->>U: Redirect to /profile
```

*Three distinct vulnerability classes in the file upload surface: ZIP path traversal (ZIP slip), XML External Entity injection with `noent: true`, and Server-Side Request Forgery via profile image URL upload.*

### 3.4 OAuth / Google Login Flow

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant SPA as Angular SPA
    participant GOOGLE as Google OAuth
    participant API as Express API

    U->>SPA: Click "Login with Google"
    SPA->>SPA: Build OAuth URL
    Note over SPA: response_type=token (IMPLICIT FLOW - DEPRECATED!)
    Note over SPA: No state parameter - CSRF on callback possible
    Note over SPA: No PKCE - code injection possible
    SPA->>U: window.location.replace(google OAuth URL)
    U->>GOOGLE: GET /o/oauth2/v2/auth?response_type=token&...
    GOOGLE-->>U: Redirect to app callback with #access_token=...
    Note over U: ACCESS TOKEN IN URL FRAGMENT - leaks in browser history!
    U->>SPA: Load /# fragment containing access_token
    SPA->>SPA: parseRedirectUrlParams() extracts access_token from fragment
    SPA->>GOOGLE: GET userinfo with access_token
    GOOGLE-->>SPA: {email, name, ...}
    Note over SPA: Password derived: btoa(email.split('').reverse().join(''))
    Note over SPA: Predictable password based on email!
    SPA->>API: POST /api/Users {email, password: btoa(reversed_email)}
    SPA->>API: POST /rest/user/login {email, oauth: true}
    API-->>SPA: {token: JWT, bid}
    SPA->>SPA: localStorage.setItem('token', jwt)
    Note over SPA: JWT stored in localStorage (XSS risk!)
```

*The Google OAuth integration uses the deprecated implicit flow (`response_type=token`). The access token appears in the URL fragment, leaking into browser history and server logs. No `state` parameter means the callback is vulnerable to CSRF. The derived password (`btoa(reversed_email)`) is fully predictable from the user's email address.*

### 3.5 Password Reset Flow

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant API as Express API
    participant DB as SQLite

    U->>API: GET /rest/user/security-question?email=target@email
    Note over API: Security question disclosed without auth!
    API->>DB: SELECT securityQuestion WHERE user.email = ?
    DB-->>API: Security question text
    API-->>U: {question: "What is your mother's maiden name?"}

    U->>API: POST /rest/user/reset-password
    Note over API: Rate limited: 100 req/5min (bypassable via X-Forwarded-For)
    API->>DB: SecurityAnswerModel.findOne() WHERE user.email = email
    API->>API: security.hmac(answer) === data.answer
    Note over API: HMAC secret is hardcoded 'pa4qacea4VK9t9nGv7yZtwmj'
    Note over API: Security answers publicly guessable for seeded users!
    API->>DB: user.update({password: newPassword})
    Note over API: No current password required for reset
    Note over API: No notification sent to account owner
    API-->>U: 200 {user: updatedUser}
```

*Security questions are disclosed without authentication. The rate limit is trivially bypassable by spoofing the `X-Forwarded-For` header. The HMAC secret for answer hashing is hardcoded. For seeded challenge users, the answers are publicly documented.*

### 3.6 Input Validation and SQL Injection Surface

```mermaid
sequenceDiagram
    participant A as Attacker (Browser)
    participant API as Express API
    participant DB as SQLite

    Note over A: SQL Injection via Search
    A->>API: GET /rest/products/search?q=')) UNION SELECT...
    API->>API: criteria = req.query.q (NO sanitization)
    API->>DB: SELECT * FROM Products WHERE name LIKE '%{criteria}%'
    Note over DB: Raw string concatenation - full UNION injection!
    DB-->>API: Products + injected data (user records, schema)
    API-->>A: 200 JSON with all user emails + passwords

    Note over A: SSTI via Username
    A->>API: PUT /api/Users/6 {username: '#{7*7}'}
    API->>DB: UPDATE Users SET username='#{7*7}'
    Note over API: User profile render via userProfile.ts
    A->>API: GET /profile
    API->>API: username.match(/#\{(.*)\}/)
    API->>API: eval(code) - SSTI to RCE!
    API-->>A: 200 HTML with eval'd expression result

    Note over A: RCE via B2B Orders
    A->>API: POST /b2b/v2/orders {orderLinesData: 'while(true){}'}
    Note over API: isAuthorized() middleware applied
    API->>API: safeEval(orderLinesData) in VM sandbox
    Note over API: VM sandbox escape possible for RCE
    API-->>A: 503 (DoS) or RCE if sandbox escaped
```

*Two confirmed SQL injection points (login and search), Server-Side Template Injection via username field (`eval()`), and sandbox escape potential in the B2B order endpoint.*

---

## 4. Assets

| Asset | Classification | Description |
|-------|---------------|-------------|
| User credentials (email + MD5 password hash) | Confidential | Stored in SQLite `Users` table; hashed with MD5 which is trivially reversible for common passwords |
| JWT RSA private key | Restricted | Hardcoded in [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23); controls authentication for all users including admin |
| TOTP secrets (2FA) | Confidential | Stored in plaintext in SQLite `Users.totpSecret` column |
| User payment card data | Confidential | Stored in SQLite `Cards` table (sample data only in training use) |
| User order history | Internal | Stored in MarsDB `ordersCollection` indexed by email |
| Product reviews and feedback | Internal | MarsDB `reviewsCollection` + SQLite `Feedbacks` |
| Application source code and challenge metadata | Internal | Served via `/snippets/:challenge` endpoints, `/api/Challenges` |
| Access logs | Internal | Written to `logs/access.log.*` files, exposed at `/support/logs/` |
| Prometheus metrics | Internal | Full application metrics exposed unauthenticated at `/metrics` |
| FTP directory contents | Internal | Files browsable at `/ftp` including `acquisitions.md`, `legal.md` |
| Encryption keys directory | Internal | Key files browsable and downloadable at `/encryptionkeys/` |
| SQLite database file | Restricted | `data/juiceshop.sqlite` — all relational data |
| HMAC secret (security answers) | Restricted | Hardcoded `pa4qacea4VK9t9nGv7yZtwmj` in [`lib/insecurity.ts:44`](vscode://file/root/juice-shop/lib/insecurity.ts:44) |

---

## 5. Attack Surface

| Entry Point | Protocol/Method | Authentication | Notes |
|-------------|----------------|----------------|-------|
| `POST /rest/user/login` | HTTP POST / JSON | None | SQL injection, no rate limit |
| `GET /rest/products/search?q=` | HTTP GET | None | SQL injection via raw string concat |
| `POST /file-upload` | HTTP POST / multipart | None required | XXE, ZIP slip, YAML bomb |
| `POST /profile/image/url` | HTTP POST / JSON | Cookie token | SSRF via user-supplied URL |
| `PUT /api/Products/:id` | HTTP PUT / JSON | **NONE** (auth middleware commented out) | Unauthenticated product modification |
| `GET /profile` | HTTP GET | Cookie token | SSTI via username → eval() |
| `POST /b2b/v2/orders` | HTTP POST / JSON | JWT Bearer | RCE/DoS via safeEval in VM sandbox |
| `GET /metrics` | HTTP GET | None | Full Prometheus metrics exposed |
| `GET /api-docs` | HTTP GET | None | Full Swagger API documentation exposed |
| `GET /ftp/` | HTTP GET | None | Directory listing + file download |
| `GET /support/logs/` | HTTP GET | None | Access log directory listing and download |
| `GET /encryptionkeys/` | HTTP GET | None | Encryption key directory listing |
| `GET /api/Challenges` | HTTP GET | None | Challenge list with descriptions |
| `GET /rest/admin/application-configuration` | HTTP GET | None | Full application config disclosed |
| `GET /rest/admin/application-version` | HTTP GET | None | Version disclosure |
| `GET /rest/user/security-question?email=` | HTTP GET | None | Security question disclosed without auth |
| `GET /rest/user/authentication-details` | HTTP GET | JWT Bearer | All active authenticated user sessions |
| `POST /rest/user/reset-password` | HTTP POST / JSON | None | Rate limit bypassable via X-Forwarded-For |
| `GET /api/Users` | HTTP GET | JWT Bearer | Full user list (emails, roles) |
| `POST /api/Users` | HTTP POST / JSON | None | User registration (role injection possible) |
| `GET /rest/basket/:id` | HTTP GET | JWT Bearer | IDOR — no ownership check on basket ID |
| `PATCH /rest/products/reviews` | HTTP PATCH / JSON | JWT Bearer | NoSQL injection in review update |
| `POST /rest/products/:id/reviews` | HTTP PUT | None | Unauthenticated review creation |
| `GET /rest/track-order/:id` | HTTP GET | None | Order tracking without auth |
| `GET /redirect?to=` | HTTP GET | None | Open redirect |
| `GET /.well-known/` | HTTP GET | None | Security policy files, directory listing |
| WebSocket `/socket.io` | WebSocket | None | Challenge notifications |

**Unauthenticated endpoints of concern:** 14 out of 25 key entry points require no authentication.

---

## 6. Trust Boundaries

**Boundary 1: Public Internet → Express Application**
Any user on the internet can reach all Express routes directly on port 3000. No WAF, reverse proxy, CDN, or API gateway exists between the public internet and the application code. Rate limiting is applied only to 3 specific endpoints.

**Boundary 2: Angular SPA → Express REST API**
The SPA communicates with the API via HTTP with JWT Bearer tokens stored in `localStorage`. The Angular route guards (`LoginGuard`, `AdminGuard`, `AccountingGuard`) provide client-side access control only — they are completely bypassable by making direct API calls. Server-side JWT validation exists but is inconsistently applied.

**Boundary 3: Express Application → SQLite Database**
SQLite runs as a file embedded in the same container filesystem. Access control between application and database tiers is entirely within the Node.js process — there is no network boundary. A process-level compromise (e.g., via `eval()`) gives immediate read/write access to the database file.

**Boundary 4: Express Application → MarsDB (MongoDB-like)**
MarsDB is an in-memory document store initialized at runtime. It holds orders and product reviews. Like SQLite, it runs in the same process with no network boundary. NoSQL injection is present in review update endpoints.

**Boundary 5: Application → External Services (Google OAuth, Webhooks)**
Outbound connections to Google OAuth are initiated from the browser (not server-side). Webhook notifications to configurable URLs are sent server-side with no URL validation or allowlist enforcement.

**Boundary 6: Container → Host**
The Dockerfile runs with `USER 65532` (non-root), which is a positive control. The distroless base image limits the attack surface within the container. However, once RCE is achieved, the container filesystem (including SQLite DB) is fully accessible.

---

## 7. Identified Security Controls

**Legend:** ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness |
|--------|---------|---------------|---------------|
| **Identity & Access Management** | JWT RS256 token issuance | [`lib/insecurity.ts:56`](vscode://file/root/juice-shop/lib/insecurity.ts:56) — `jwt.sign()` with RS256 algorithm | 🔶 Weak — private key is hardcoded in source, anyone can forge tokens |
| **Identity & Access Management** | JWT verification middleware | [`lib/insecurity.ts:54`](vscode://file/root/juice-shop/lib/insecurity.ts:54) — `expressJwt()` applied on selected routes | ⚠️ Partial — not applied to all state-changing routes (e.g., product update commented out) |
| **Identity & Access Management** | 2FA (TOTP) support | [`routes/2fa.ts`](vscode://file/root/juice-shop/routes/2fa.ts) — `otplib` TOTP with rate limiting on verify endpoint | ⚠️ Partial — optional, not enforced; TOTP secret stored in plaintext in DB |
| **Identity & Access Management** | Password hashing | [`lib/insecurity.ts:43`](vscode://file/root/juice-shop/lib/insecurity.ts:43) — `crypto.createHash('md5')` | ❌ Missing adequate hashing — MD5 is not a password hash (no salt, fast computation) |
| **Identity & Access Management** | Account lockout | Not found | ❌ Missing — no brute-force protection on login |
| **Authorization** | Role-based access control (RBAC) | [`lib/insecurity.ts:144-175`](vscode://file/root/juice-shop/lib/insecurity.ts:144) — `isAccounting()`, `isDeluxe()`, `isCustomer()` | ⚠️ Partial — roles defined but forgeable via hardcoded private key |
| **Authorization** | Route-level auth middleware | [`server.ts:354-453`](vscode://file/root/juice-shop/server.ts:354) — `security.isAuthorized()` on selected routes | ⚠️ Partial — inconsistently applied; `PUT /api/Products/:id` has no middleware |
| **Authorization** | Client-side route guards | [`app.guard.ts`](vscode://file/root/juice-shop/frontend/src/app/app.guard.ts) — `LoginGuard`, `AdminGuard`, `AccountingGuard` | 🔶 Weak — client-side only, entirely bypassable |
| **Data Protection** | HTTPS/TLS | Not configured by default — `http.Server` in [`server.ts:130`](vscode://file/root/juice-shop/server.ts:130) | 🔶 Weak — HTTP only by default; TLS requires external configuration |
| **Data Protection** | Password encryption at rest | MD5 hash only (no salt) | ❌ Missing — MD5 hashes are trivially crackable with rainbow tables |
| **Data Protection** | TOTP secret storage | Stored plaintext in `totpSecret` DB column | 🔶 Weak — should be encrypted at rest |
| **Secret Management** | Secrets externalization | RSA private key hardcoded at [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23); cookie secret `kekse` at [`server.ts:289`](vscode://file/root/juice-shop/server.ts:289); HMAC secret at [`lib/insecurity.ts:44`](vscode://file/root/juice-shop/lib/insecurity.ts:44) | ❌ Missing — all critical secrets hardcoded in source code |
| **Frontend Security** | Helmet security headers | [`server.ts:185-186`](vscode://file/root/juice-shop/server.ts:185) — `helmet.noSniff()`, `helmet.frameguard()` | ⚠️ Partial — `xssFilter` explicitly disabled, no `Content-Security-Policy` from Helmet (CSP set only on profile page with `unsafe-eval`) |
| **Frontend Security** | HTML sanitization | [`lib/insecurity.ts:60-70`](vscode://file/root/juice-shop/lib/insecurity.ts:60) — `sanitize-html 1.4.2` | 🔶 Weak — outdated `sanitize-html` (1.4.2) with known bypasses; `sanitizeLegacy()` uses regex which is easily bypassed |
| **Frontend Security** | CSRF protection | None | ❌ Missing — no CSRF tokens; SameSite cookie attribute not configured |
| **Output Encoding** | Parameterized queries | Sequelize ORM used for most queries | ⚠️ Partial — ORM bypassed with raw SQL in login ([`routes/login.ts:34`](vscode://file/root/juice-shop/routes/login.ts:34)) and search ([`routes/search.ts:23`](vscode://file/root/juice-shop/routes/search.ts:23)) |
| **Output Encoding** | NoSQL injection prevention | MarsDB queries in `/rest/products/reviews` | ❌ Missing — review update endpoint vulnerable to NoSQL injection |
| **Audit & Logging** | HTTP access logging | [`server.ts:330-338`](vscode://file/root/juice-shop/server.ts:330) — Morgan combined format to rotating log files | ⚠️ Partial — HTTP requests logged, but no structured security event logging (login failures, permission denials, etc.) |
| **Audit & Logging** | Security event logging | Not found — no dedicated auth/access failure logging | ❌ Missing — no SIEM-compatible structured security events |
| **Infrastructure & Network** | Non-root container user | [`Dockerfile:39-40`](vscode://file/root/juice-shop/Dockerfile:39) — `USER 65532` with distroless base image | ✅ Adequate — container runs as non-root user with minimal OS footprint |
| **Infrastructure & Network** | CORS policy | [`server.ts:181-182`](vscode://file/root/juice-shop/server.ts:181) — `cors()` with no options = wildcard | ❌ Missing adequate control — wildcard CORS allows any origin |
| **Infrastructure & Network** | Rate limiting | [`server.ts:343-347`](vscode://file/root/juice-shop/server.ts:343) — `express-rate-limit` on reset-password and 2FA endpoints | ⚠️ Partial — only 3 endpoints rate-limited; login has no rate limit; rate limit bypassable via `X-Forwarded-For` spoofing |
| **Dependency & Supply Chain** | Lock files | No `package-lock.json` found at root or frontend | ❌ Missing — no lock files, dependencies resolved at install time |
| **Dependency & Supply Chain** | Dependency versions | [`package.json`](vscode://file/root/juice-shop/package.json) — `jsonwebtoken: 0.4.0`, `express-jwt: 0.1.3`, `sanitize-html: 1.4.2`, `unzipper: 0.9.15` | 🔶 Weak — multiple critically outdated packages with known CVEs |
| **Dependency & Supply Chain** | SBOM generation | [`package.json:74`](vscode://file/root/juice-shop/package.json:74) — `npm run sbom` generates `bom.json` via CycloneDX | ✅ Adequate — SBOM generation present and run as part of Docker build |
| **Security Testing & Pipeline** | SAST (CodeQL) | [`.github/workflows/codeql-analysis.yml`](vscode://file/root/juice-shop/.github/workflows/codeql-analysis.yml) — CodeQL with `security-extended` queries | ✅ Adequate — CodeQL runs on all branches with extended security queries |
| **Security Testing & Pipeline** | DAST (OWASP ZAP) | [`.github/workflows/zap_scan.yml`](vscode://file/root/juice-shop/.github/workflows/zap_scan.yml) — ZAP baseline scan | ⚠️ Partial — ZAP scan present but baseline only (not full active scan) |
| **OAuth / OIDC Implementation** | OAuth implicit flow | [`login.component.ts:134`](vscode://file/root/juice-shop/frontend/src/app/login/login.component.ts:134) — `response_type=token` | ❌ Missing — deprecated implicit flow; no PKCE, no state validation |
| **SPA / BFF Architecture** | Token storage | [`app.guard.ts:18`](vscode://file/root/juice-shop/frontend/src/app/app.guard.ts:18) — `localStorage.getItem('token')` | ❌ Missing secure storage — tokens in `localStorage` accessible to XSS |
| **SPA / BFF Architecture** | BFF pattern | Not present | ❌ Missing — SPA holds JWT directly; no backend-for-frontend token proxy |

**Narrative summary of gaps:**

The most structurally significant gaps are: (1) hardcoded RSA private key making JWT-based authentication meaningless as a security control; (2) MD5 password hashing making all user passwords recoverable via rainbow tables; (3) raw SQL in login and search routes enabling trivial authentication bypass and data exfiltration; (4) wildcard CORS combined with localStorage token storage making any XSS universally impactful; and (5) no CSRF protection on state-changing endpoints. These are all intentional for training purposes but represent the complete absence of effective security controls.

---

## 8. Threat Register

**Purpose:** Describes what can go wrong and why. Remediation details are in Section 10.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | Auth Service | Spoofing | The RSA private key for JWT signing is hardcoded in [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23). Any attacker with source code access (public GitHub repo) can generate a valid JWT with `role: admin` and `data.email: admin@juice-sh.op`, impersonating any user including administrators without knowing credentials. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | JWT signature verification via public key | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | Angular SPA | Information Disclosure | JWT tokens are stored in `localStorage` at [`app.guard.ts:18`](vscode://file/root/juice-shop/frontend/src/app/app.guard.ts:18) and [`request.interceptor.ts:13`](vscode://file/root/juice-shop/frontend/src/app/Services/request.interceptor.ts:13). Any XSS vulnerability (of which many exist intentionally) can exfiltrate the token via `document.cookie` or `localStorage.getItem('token')`, granting full account access. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-002](#m-002) |
| <a id="t-003"></a>T-003 | REST API — Search | Tampering | Raw SQL string concatenation in [`routes/search.ts:23`](vscode://file/root/juice-shop/routes/search.ts:23): `SELECT * FROM Products WHERE name LIKE '%${criteria}%'`. Attacker sends `q=')) UNION SELECT id,email,password,role,NULL,NULL,NULL,NULL FROM Users--` to extract all user credentials without authentication. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None — no auth required on search | [M-003](#m-003) |
| <a id="t-004"></a>T-004 | REST API — Login | Spoofing | Raw SQL in [`routes/login.ts:34`](vscode://file/root/juice-shop/routes/login.ts:34): `SELECT * FROM Users WHERE email='${email}'`. Attacker sends `email: admin@juice-sh.op'--` with any password, commenting out the password check. Grants admin authentication without credentials. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-003](#m-003) |
| <a id="t-005"></a>T-005 | REST API — UserProfile | Elevation of Privilege | Server-Side Template Injection via `eval()` in [`routes/userProfile.ts:62`](vscode://file/root/juice-shop/routes/userProfile.ts:62). Username containing `#{process.mainModule.require('child_process').exec('id')}` is evaluated as JavaScript, enabling Remote Code Execution on the server in the context of the Node.js process (UID 65532 in Docker). | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | Runs as non-root (UID 65532) | [M-004](#m-004) |
| <a id="t-006"></a>T-006 | File Upload Handler | Information Disclosure | XML External Entity injection in [`routes/fileUpload.ts:83`](vscode://file/root/juice-shop/routes/fileUpload.ts:83): `libxml.parseXml(data, { noent: true })`. Attacker uploads XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` to read server-side files. The file content is reflected back in the error message at line 87. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | None | [M-005](#m-005) |
| <a id="t-007"></a>T-007 | File Upload Handler | Elevation of Privilege | ZIP path traversal in [`routes/fileUpload.ts:44`](vscode://file/root/juice-shop/routes/fileUpload.ts:44). The path check `absolutePath.includes(path.resolve('.'))` is insufficient — ZIP entries with path `../../ftp/legal.md` can overwrite files outside the upload directory. The challenge explicitly tests writing to `ftp/legal.md`. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-005](#m-005) |
| <a id="t-008"></a>T-008 | OAuth Integration | Information Disclosure | OAuth implicit flow (`response_type=token`) used in [`login.component.ts:134`](vscode://file/root/juice-shop/frontend/src/app/login/login.component.ts:134). The Google access token appears in the URL fragment (`#access_token=...`), leaking into browser history, server logs, and `Referer` headers. No `state` parameter means the callback is CSRF-vulnerable. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-006](#m-006) |
| <a id="t-009"></a>T-009 | Profile Image Upload | Denial of Service | SSRF via [`routes/profileImageUrlUpload.ts:24`](vscode://file/root/juice-shop/routes/profileImageUrlUpload.ts:24): `fetch(url)` with no URL validation. Attacker provides internal URLs (`http://169.254.169.254/latest/meta-data/` for cloud IMDS, or `http://localhost:3000/api/Users` for internal pivot). Also enables DoS by pointing to slow/large resources. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Requires auth (cookie) | [M-007](#m-007) |
| <a id="t-010"></a>T-010 | REST API — Multiple | Tampering | Stored XSS: the `persistedXssUserChallenge` mode in [`models/user.ts:49-55`](vscode://file/root/juice-shop/models/user.ts:49) uses `sanitizeLegacy()` (regex-based, easily bypassed) instead of `sanitizeSecure()`. Email field with `<iframe src="javascript:alert()">` is stored and rendered to all users viewing that account, persisting XSS across sessions. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | `sanitizeLegacy()` (bypassable) | [M-008](#m-008) |
| <a id="t-011"></a>T-011 | REST API — Password | Spoofing | MD5 password hashing in [`lib/insecurity.ts:43`](vscode://file/root/juice-shop/lib/insecurity.ts:43): `crypto.createHash('md5')`. MD5 hashes are trivially reversible via precomputed rainbow tables. If the database is exfiltrated (via SQLi or direct access), all user passwords can be recovered, enabling credential stuffing against other services. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | None | [M-009](#m-009) |
| <a id="t-012"></a>T-012 | REST API — General | Repudiation | No structured security event logging in any route handler. Login failures, permission denials, and data access events are not logged to an audit trail. Access logs are written via Morgan but are accessible unauthenticated at `/support/logs/` ([`server.ts:281-283`](vscode://file/root/juice-shop/server.ts:281)). An attacker can cover tracks by reading logs to understand detection patterns. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | Morgan HTTP access log | [M-010](#m-010) |
| <a id="t-013"></a>T-013 | REST API — Metrics | Information Disclosure | Prometheus metrics endpoint at `/metrics` is unauthenticated ([`server.ts:718`](vscode://file/root/juice-shop/server.ts:718)). Exposes request counts by status code, file upload metrics, user counts, wallet balances, challenge progress, cheat scores, and potentially memory/CPU data. Discloses internal topology and usage patterns to attackers. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-011](#m-011) |
| <a id="t-014"></a>T-014 | REST API — CORS | Information Disclosure | Wildcard CORS (`cors()` with no options) in [`server.ts:181-182`](vscode://file/root/juice-shop/server.ts:181) allows any origin to make credentialed cross-origin requests. Combined with `localStorage` token storage, a malicious page can use XHR/fetch to call the Juice Shop API with a stolen or forged Bearer token from any domain. | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-012](#m-012) |
| <a id="t-015"></a>T-015 | Dependency Chain | Tampering | `jsonwebtoken 0.4.0` (package.json:156) is over 10 years old and predates critical security patches including algorithm confusion attacks. `express-jwt 0.1.3` predates fixes for header injection and algorithm bypass. Both are used in the authentication path in [`lib/insecurity.ts`](vscode://file/root/juice-shop/lib/insecurity.ts). | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | CodeQL SAST runs on repo | [M-013](#m-013) |
| <a id="t-016"></a>T-016 | REST API — Rate Limiting | Denial of Service | No rate limiting on `POST /rest/user/login`. The reset-password rate limit ([`server.ts:343-347`](vscode://file/root/juice-shop/server.ts:343)) trusts `X-Forwarded-For` for the key generator — trivially bypassed by rotating this header. An attacker can brute-force login credentials or enumerate user accounts without throttling. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Partial rate limit on reset-password | [M-014](#m-014) |
| <a id="t-017"></a>T-017 | Angular SPA | Elevation of Privilege | Client-side authorization guards in [`app.guard.ts`](vscode://file/root/juice-shop/frontend/src/app/app.guard.ts) check `localStorage.getItem('token')` and decode the JWT client-side with `jwtDecode` (without signature verification) to determine roles. Any user can craft a JWT payload with `role: admin` stored in `localStorage` to bypass the Angular route guard UI, then make direct API calls with a forged signed token. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Server-side JWT verification on some routes | [M-015](#m-015) |
| <a id="t-018"></a>T-018 | REST API — Open Redirect | Spoofing | Open redirect in [`routes/redirect.ts:16-19`](vscode://file/root/juice-shop/routes/redirect.ts:16). The `isRedirectAllowed()` function at [`lib/insecurity.ts:135-141`](vscode://file/root/juice-shop/lib/insecurity.ts:135) checks if the URL **contains** an allowlisted URL (not exact match), so `https://evil.com?x=https://github.com/juice-shop/juice-shop` passes the check and redirects to the attacker site. Used for phishing. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Partial allowlist (bypassable) | [M-016](#m-016) |
| <a id="t-019"></a>T-019 | REST API — IDOR | Elevation of Privilege | Insecure Direct Object Reference: `GET /rest/basket/:id` and related basket endpoints do not verify that the authenticated user owns the requested basket ID. An authenticated user can access any other user's basket by iterating integer IDs. Same pattern in address and order history endpoints. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | Authentication required | [M-017](#m-017) |
| <a id="t-020"></a>T-020 | REST API — Unprotected Route | Elevation of Privilege | `PUT /api/Products/:id` has no authentication middleware — the `isAuthorized()` call is explicitly commented out at [`server.ts:369`](vscode://file/root/juice-shop/server.ts:369). Any unauthenticated user can modify any product's price, description, or image, enabling free products or reputation attacks. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-018](#m-018) |
| <a id="t-021"></a>T-021 | File Upload Handler | Denial of Service | YAML bomb attack via file upload in [`routes/fileUpload.ts:109-138`](vscode://file/root/juice-shop/routes/fileUpload.ts:109). A YAML file containing deeply nested anchors and aliases can expand to gigabytes in memory when parsed by `js-yaml`, exhausting server memory and causing a DoS. The 2-second timeout in `vm.runInContext` mitigates but does not prevent memory exhaustion before the timeout fires. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | 2-second VM timeout | [M-005](#m-005) |
| <a id="t-022"></a>T-022 | REST API — Security Questions | Spoofing | Security questions disclosed without authentication at `GET /rest/user/security-question?email=`. Answers are predictable/researched for seeded accounts and hashed with a hardcoded HMAC key (`pa4qacea4VK9t9nGv7yZtwmj`). Account takeover via password reset requires only guessing a memorable question answer. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | HMAC hashing of answers (key hardcoded) | [M-009](#m-009) |
| <a id="t-023"></a>T-023 | OAuth Integration | Spoofing | OAuth account registration derives password from email: `btoa(email.split('').reverse().join(''))` at [`oauth.component.ts:30`](vscode://file/root/juice-shop/frontend/src/app/oauth/oauth.component.ts:30). Any attacker who knows a victim's email can call `POST /rest/user/login` with the derived password to log in as that user without Google OAuth. | <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None — password is deterministic | [M-006](#m-006) |
| <a id="t-024"></a>T-024 | Dependency Chain | Information Disclosure | `unzipper 0.9.15` has CVE-2020-12265 (path traversal). `sanitize-html 1.4.2` has multiple known XSS bypass CVEs. No lock files ensure reproducible builds. No Dependabot or automated dependency update configured. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | SBOM generation via CycloneDX | [M-013](#m-013) |
| <a id="t-025"></a>T-025 | REST API — Admin Routes | Information Disclosure | `GET /rest/admin/application-configuration` and `GET /rest/admin/application-version` at [`server.ts:604-605`](vscode://file/root/juice-shop/server.ts:604) require no authentication. Full application config (including Google OAuth client IDs, server URLs, feature flags) disclosed to any requester. | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | None | [M-011](#m-011) |

---

## 9. Critical Findings

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-001 — Hardcoded JWT Private Key Enables Universal Authentication Bypass

**Scenario:** The RSA private key used to sign all JWTs is hardcoded as a string literal in the public GitHub repository at [`lib/insecurity.ts:23`](vscode://file/root/juice-shop/lib/insecurity.ts:23). Any person who has ever seen the source code can craft a valid JWT with any user identity and role (including `role: admin`) and send it as a Bearer token to any protected endpoint. This bypasses all authentication controls in the application.

**Current state:** Private key is a hardcoded 1024-bit RSA PEM string starting at line 23 of `lib/insecurity.ts`. The `security.authorize()` function at line 56 uses this key directly. The public key is read from `encryptionkeys/jwt.pub` on disk.

→ **Mitigation:** [M-001 — Load JWT signing key from environment variable or secrets manager](#m-001)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-003 — Unauthenticated SQL Injection on Product Search Enables Full Database Exfiltration

**Scenario:** The product search endpoint at `GET /rest/products/search?q=` builds its SQL query via string concatenation at [`routes/search.ts:23`](vscode://file/root/juice-shop/routes/search.ts:23). No authentication is required. An attacker sends `')) UNION SELECT id,email,password,username,role,NULL,NULL,NULL FROM Users--` to extract all user emails, MD5 password hashes, and roles in a single unauthenticated HTTP request.

**Current state:** Raw SQL: `` `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL)` `` — no parameterization, no auth.

→ **Mitigation:** [M-003 — Replace raw SQL with Sequelize parameterized queries](#m-003)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-005 — Server-Side Template Injection via eval() in User Profile Enables RCE

**Scenario:** The user profile rendering in [`routes/userProfile.ts:55-65`](vscode://file/root/juice-shop/routes/userProfile.ts:55) checks if the username matches `#{...}` and executes the content with `eval(code)`. Any authenticated user can update their username to `#{process.mainModule.require('child_process').execSync('cat /etc/passwd').toString()}` to achieve Remote Code Execution on the server.

**Current state:** `eval(code)` at line 62 of `routes/userProfile.ts` executes user-controlled string as JavaScript with no sandboxing.

→ **Mitigation:** [M-004 — Remove eval() from user profile rendering and use safe template rendering](#m-004)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-006 — XXE Injection in File Upload Enables Server File Disclosure

**Scenario:** The XML file upload handler at [`routes/fileUpload.ts:83`](vscode://file/root/juice-shop/routes/fileUpload.ts:83) parses XML with `{ noent: true }` which enables external entity expansion. An attacker uploads an XML file containing `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and the content of `/etc/passwd` (or the SQLite database) is reflected in the 410 error response body.

**Current state:** `libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })` at line 83 of `routes/fileUpload.ts`. The `noent: true` flag explicitly enables the XXE vulnerability.

→ **Mitigation:** [M-005 — Disable external entity expansion in XML parser](#m-005)

---

### <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> T-004 — SQL Injection on Login Enables Authentication Bypass

**Scenario:** The login query at [`routes/login.ts:34`](vscode://file/root/juice-shop/routes/login.ts:34) concatenates user input directly into SQL. Sending `email: "' OR '1'='1'--"` logs in as the first user in the database. Sending `email: "admin@juice-sh.op'--"` with any password logs in as the admin user specifically. No rate limiting on this endpoint enables automated exploitation.

**Current state:** `` `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL` `` — raw string concatenation with no sanitization or parameterization.

→ **Mitigation:** [M-003 — Replace raw SQL with Sequelize parameterized queries](#m-003)

---

## 10. Mitigation Register

### <a id="m-001"></a>M-001 · Load JWT Signing Key from Environment Variable or Secrets Manager

**Addresses:** [T-001](#t-001)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Medium

**Why:** The hardcoded private key means anyone with repo access can forge any user's JWT, completely bypassing authentication for all protected endpoints.

**How:**
1. Remove the hardcoded `privateKey` string from `lib/insecurity.ts`
2. Load the key from an environment variable or mounted secret at startup:
   `const privateKey = process.env.JWT_PRIVATE_KEY ?? fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE ?? 'encryptionkeys/jwt.pem', 'utf8')`
3. Generate a new RSA key pair for each deployment: `openssl genrsa -out jwt.pem 2048 && openssl rsa -in jwt.pem -pubout -out jwt.pub`
4. Store the private key in Docker secrets, HashiCorp Vault, or AWS Secrets Manager
5. Rotate the key and invalidate all existing tokens when the compromise is detected

```typescript
// Before (lib/insecurity.ts:23)
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIIC...'

// After
const privateKey = process.env.JWT_PRIVATE_KEY
  ?? (() => {
    const keyFile = process.env.JWT_PRIVATE_KEY_FILE
    if (!keyFile) throw new Error('JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE must be set')
    return fs.readFileSync(keyFile, 'utf8')
  })()
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

---

### <a id="m-002"></a>M-002 · Move JWT Token Storage from localStorage to HttpOnly Cookie

**Addresses:** [T-002](#t-002)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** High

**Why:** Tokens in `localStorage` are accessible to any JavaScript running on the page, making any XSS vulnerability an authentication bypass rather than just a page defacement.

**How:**
1. Modify the login endpoint to set the JWT in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie instead of returning it in the response body
2. Remove `localStorage.setItem('token', ...)` from all SPA components
3. Update Angular's `request.interceptor.ts` to remove the `Authorization: Bearer` header injection (the HttpOnly cookie will be sent automatically)
4. Update `lib/insecurity.ts` `isAuthorized()` to read the token from `req.cookies.token` rather than the Authorization header
5. Add CSRF protection (double-submit cookie or synchronizer token) since cookie-based auth is CSRF-vulnerable

```typescript
// Before (routes/login.ts)
res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })

// After
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 6 * 60 * 60 * 1000 // 6 hours matching JWT expiry
})
res.json({ authentication: { bid: basket.id, umail: user.data.email } })
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

---

### <a id="m-003"></a>M-003 · Replace Raw SQL String Concatenation with Parameterized Queries

**Addresses:** [T-003](#t-003), [T-004](#t-004)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** Raw SQL concatenation with user input enables authentication bypass and complete database exfiltration via UNION injection.

**How:**
1. Replace the raw query in `routes/login.ts` with a Sequelize `findOne` with `where` clause
2. Replace the raw query in `routes/search.ts` with a Sequelize `Op.like` parameterized query
3. Audit all other uses of `models.sequelize.query()` for similar concatenation patterns

```typescript
// Before (routes/login.ts:34) — SQL injection
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`
)

// After — parameterized
UserModel.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password),
    deletedAt: null
  }
})

// Before (routes/search.ts:23) — SQL injection
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL)`
)

// After — parameterized
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

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

---

### <a id="m-004"></a>M-004 · Remove eval() from User Profile Rendering and Use Safe Template Logic

**Addresses:** [T-005](#t-005)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** `eval()` on user-controlled input enables Remote Code Execution — any authenticated user can execute arbitrary Node.js code on the server.

**How:**
1. Remove the `eval(code)` block at lines 55-65 of `routes/userProfile.ts` entirely
2. Render the username as a plain string with HTML entity encoding instead of template evaluation
3. The Pug template (`views/userProfile.pug`) should receive the username as escaped data, not as raw HTML

```typescript
// Before (routes/userProfile.ts:55-65)
if (username?.match(/#{(.*)}/) !== null && ...) {
  const code = username?.substring(2, username.length - 1)
  username = eval(code) // RCE!
}

// After — remove the eval block entirely
// username is already set from user.username above
// Pass to template as escaped data, not evaluated code
```

**Reference:** https://owasp.org/www-community/attacks/Server-Side_Template_Injection — CWE-94

---

### <a id="m-005"></a>M-005 · Disable External Entity Expansion and Validate Archive Entry Paths

**Addresses:** [T-006](#t-006), [T-007](#t-007), [T-021](#t-021)
**Priority:** <span style="background:#b91c1c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Critical</span> | **Effort:** Low

**Why:** XXE with `noent: true` enables server file read. ZIP slip allows writing files outside the intended upload directory. YAML bombs exhaust server memory.

**How:**
1. Change `noent: true` to `noent: false` in the `libxml.parseXml()` call at `routes/fileUpload.ts:83`
2. Replace the insufficient path check `absolutePath.includes(path.resolve('.'))` with a strict prefix check
3. Add a file size limit before YAML parsing to prevent memory exhaustion

```typescript
// Before (routes/fileUpload.ts:83)
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox)

// After — disable external entities
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })', sandbox)

// Before (routes/fileUpload.ts:44) — insufficient path check
if (absolutePath.includes(path.resolve('.'))) {
  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))
}

// After — strict path prefix check
const safeBase = path.resolve('uploads/complaints')
if (absolutePath.startsWith(safeBase + path.sep)) {
  entry.pipe(fs.createWriteStream(absolutePath))
} else {
  entry.autodrain()
}
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html — CWE-611

---

### <a id="m-006"></a>M-006 · Replace OAuth Implicit Flow with Authorization Code + PKCE

**Addresses:** [T-008](#t-008), [T-023](#t-023)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** High

**Why:** The implicit flow exposes tokens in URLs, enabling token leakage via browser history, `Referer` headers, and server logs. The derived password from email is fully predictable.

**How:**
1. Replace `response_type=token` with `response_type=code` in the Google OAuth URL construction at `login.component.ts:134`
2. Implement PKCE: generate a `code_verifier`, compute `code_challenge = base64url(sha256(verifier))`, send `code_challenge` in the authorization request
3. Exchange the authorization code for tokens server-side (not in the browser) via a BFF or proxy endpoint
4. Validate the `state` parameter on callback to prevent CSRF
5. Replace the deterministic password derivation with a random password or remove the password-based fallback entirely

```typescript
// Before (login.component.ts:134)
`${oauthProviderUrl}?client_id=${this.clientId}&response_type=token&scope=email&redirect_uri=${this.redirectUri}`

// After — authorization code + PKCE
const codeVerifier = generateCodeVerifier()  // crypto.randomBytes(32)
const codeChallenge = await computeCodeChallenge(codeVerifier)  // base64url(sha256(verifier))
const state = crypto.randomUUID()
sessionStorage.setItem('oauth_state', state)
sessionStorage.setItem('code_verifier', codeVerifier)
`${oauthProviderUrl}?client_id=${this.clientId}&response_type=code&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}&scope=email&redirect_uri=${this.redirectUri}`
```

**Reference:** https://oauth.net/2/pkce/ — RFC 7636, RFC 9700

---

### <a id="m-007"></a>M-007 · Validate and Allowlist URLs in Profile Image Upload to Prevent SSRF

**Addresses:** [T-009](#t-009)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Server-side fetch of user-supplied URLs enables SSRF attacks against internal services including cloud IMDS endpoints and internal APIs.

**How:**
1. Parse the URL and validate the scheme is `https` only (reject `http`, `file`, `ftp`, internal protocols)
2. Resolve the hostname to an IP and reject private/loopback/link-local ranges (RFC 1918, `169.254.0.0/16`, `::1`, etc.)
3. Set a strict timeout and maximum response size on the fetch call
4. Consider using a separate image proxy service for fetching external images

```typescript
// Before (routes/profileImageUrlUpload.ts:24)
const response = await fetch(url)

// After — with URL validation
import { URL } from 'url'
function isAllowedUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl)
    if (parsed.protocol !== 'https:') return false
    const hostname = parsed.hostname
    // Reject private/internal ranges
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(hostname)) return false
    return true
  } catch { return false }
}
if (!isAllowedUrl(url)) throw new Error('URL not allowed')
const response = await fetch(url, { signal: AbortSignal.timeout(5000) })
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — CWE-918

---

### <a id="m-008"></a>M-008 · Replace sanitizeLegacy() with sanitizeSecure() Consistently

**Addresses:** [T-010](#t-010)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Low

**Why:** The `sanitizeLegacy()` function uses a trivially bypassable regex — allowing stored XSS via email and username fields.

**How:**
1. Replace all instances of `sanitizeLegacy()` with `sanitizeSecure()` in `models/user.ts`
2. Upgrade `sanitize-html` from `1.4.2` to the latest version (significant security fixes applied since 1.x)
3. Apply a strict `allowedTags: []` policy for plain-text fields like email and username

```typescript
// Before (models/user.ts:50) — bypassable regex
username = security.sanitizeLegacy(username)

// After — recursive secure sanitizer
username = security.sanitizeSecure(username)
// Or better, for plain-text fields:
username = sanitizeHtmlLib(username, { allowedTags: [], allowedAttributes: {} })
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — CWE-79

---

### <a id="m-009"></a>M-009 · Replace MD5 Password Hashing with bcrypt or Argon2

**Addresses:** [T-011](#t-011), [T-022](#t-022)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** MD5 is not a password hashing algorithm — it has no salt, is extremely fast to compute, and all common passwords are in precomputed rainbow tables.

**How:**
1. Replace `crypto.createHash('md5')` in `lib/insecurity.ts:43` with bcrypt (cost factor ≥ 12)
2. On next login, re-hash any existing MD5 hashes with bcrypt (migration on authentication)
3. Replace the HMAC security answer hashing with bcrypt as well, removing the hardcoded secret

```typescript
// Before (lib/insecurity.ts:43)
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After — using bcrypt
import bcrypt from 'bcrypt'
const SALT_ROUNDS = 12
export const hash = async (data: string) => bcrypt.hash(data, SALT_ROUNDS)
export const hashCompare = async (data: string, hashed: string) => bcrypt.compare(data, hashed)
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — CWE-916

---

### <a id="m-010"></a>M-010 · Add Structured Security Event Logging and Protect Log Access

**Addresses:** [T-012](#t-012)
**Priority:** <span style="background:#ea580c;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">High</span> | **Effort:** Medium

**Why:** Without security event logging, attackers cannot be detected or investigated. Exposed logs at `/support/logs/` additionally reveal attack patterns to adversaries.

**How:**
1. Add authentication middleware to `/support/logs` (`security.isAccounting()` or `security.isAuthorized()`)
2. Add structured security event logging for: login success/failure, password change, 2FA events, permission denials, data export requests
3. Use Winston's JSON format for structured logs that can be ingested by SIEM tools

```typescript
// Add to routes/login.ts after authentication result
logger.warn({
  event: 'login_failure',
  email: req.body.email,
  ip: req.ip,
  userAgent: req.headers['user-agent'],
  timestamp: new Date().toISOString()
})

// server.ts — protect log endpoint
// Before:
app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', ...))
// After:
app.use('/support/logs', security.isAuthorized(), serveIndexMiddleware, serveIndex('logs', ...))
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html — CWE-778

---

### <a id="m-011"></a>M-011 · Restrict Access to Metrics, API Docs, and Admin Configuration Endpoints

**Addresses:** [T-013](#t-013), [T-025](#t-025)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Unauthenticated metrics and configuration endpoints disclose internal topology, user counts, and configuration to attackers for reconnaissance.

**How:**
1. Add `security.isAccounting()` or IP allowlist middleware before the `/metrics` route at `server.ts:718`
2. Add `security.isAuthorized()` before `/api-docs` to restrict Swagger UI to authenticated users
3. Add `security.isAuthorized()` before `/rest/admin/application-configuration` and `/rest/admin/application-version`

```typescript
// Before (server.ts:718)
app.get('/metrics', metrics.serveMetrics())

// After — require authentication
app.get('/metrics', security.isAccounting(), metrics.serveMetrics())

// Before (server.ts:286)
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

// After
app.use('/api-docs', security.isAuthorized(), swaggerUi.serve, swaggerUi.setup(swaggerDocument))
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html — CWE-200

---

### <a id="m-012"></a>M-012 · Replace Wildcard CORS with Explicit Origin Allowlist

**Addresses:** [T-014](#t-014)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Wildcard CORS allows any website to make API calls using the user's credentials, enabling cross-origin attacks.

**How:**
1. Replace `cors()` with `cors({ origin: config.get('server.allowedOrigins') })`
2. Configure the allowed origins list in the YAML config to include only the application's own domain(s)
3. Set `credentials: true` only if cookie-based auth is used (after implementing M-002)

```typescript
// Before (server.ts:181)
app.options('*', cors())
app.use(cors())

// After
const corsOptions = {
  origin: config.get<string[]>('server.allowedOrigins'),
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html — CWE-942

---

### <a id="m-013"></a>M-013 · Update Outdated Dependencies and Add Lock Files

**Addresses:** [T-015](#t-015), [T-024](#t-024)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** `jsonwebtoken 0.4.0` and `express-jwt 0.1.3` are over a decade old with known algorithm confusion vulnerabilities in the authentication path.

**How:**
1. Update `jsonwebtoken` to `^9.0.0` (current stable, includes algorithm allowlist enforcement)
2. Update `express-jwt` to `^8.0.0` (completely rewritten with modern security defaults)
3. Update `sanitize-html` to `^2.13.0`
4. Update `unzipper` to `^0.12.0` or replace with `adm-zip`
5. Run `npm install` with `--package-lock` to generate `package-lock.json` and commit it
6. Add Dependabot config at `.github/dependabot.yml` for automated dependency PRs

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

**Reference:** https://owasp.org/www-project-dependency-check/ — CWE-1104

---

### <a id="m-014"></a>M-014 · Add Rate Limiting to Login Endpoint and Fix Bypassable Rate Limit

**Addresses:** [T-016](#t-016)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** Unlimited login attempts enable brute-force and credential stuffing attacks. The existing rate limit is bypassable via `X-Forwarded-For` header spoofing.

**How:**
1. Add `rateLimit()` middleware to `POST /rest/user/login` before the handler
2. Remove the `keyGenerator` that trusts `X-Forwarded-For` — use `req.ip` (which is set correctly when `trust proxy` is configured for a trusted upstream only)
3. Set `app.set('trust proxy', '127.0.0.1')` only if behind a known proxy, not blindly

```typescript
// Add before login route registration (server.ts ~line 594)
const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per IP
  standardHeaders: true,
  legacyHeaders: false
  // No custom keyGenerator — use req.ip
})
app.post('/rest/user/login', loginRateLimit, login())
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html — CWE-307

---

### <a id="m-015"></a>M-015 · Remove Client-Side Authorization Checks and Enforce Server-Side Only

**Addresses:** [T-017](#t-017)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** Angular route guards are client-side only and completely bypassable by direct API calls. Authorization must be enforced server-side.

**How:**
1. Ensure every admin and accounting endpoint has `security.isAccounting()` or an equivalent server-side check in addition to the Angular guard
2. The Angular guards are acceptable as UX-level controls (prevent loading pages the user can't use) but must not be the security boundary
3. Audit all routes in `server.ts` to ensure no protected resource is accessible without server-side authorization

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — CWE-602

---

### <a id="m-016"></a>M-016 · Fix Open Redirect URL Allowlist Check to Use Exact Match

**Addresses:** [T-018](#t-018)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** The current `url.includes(allowedUrl)` check is bypassed by appending an allowlisted URL as a query parameter to an attacker-controlled domain.

**How:**
1. Replace the `includes()` check with `startsWith()` or exact URL comparison in `lib/insecurity.ts:138`
2. Normalize both URLs before comparison (remove trailing slashes, normalize query params)

```typescript
// Before (lib/insecurity.ts:138)
allowed = allowed || url.includes(allowedUrl)

// After — exact start match
allowed = allowed || url === allowedUrl || url.startsWith(allowedUrl + '?') || url.startsWith(allowedUrl + '#')
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html — CWE-601

---

### <a id="m-017"></a>M-017 · Add Ownership Verification to Basket, Address, and Order Endpoints

**Addresses:** [T-019](#t-019)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Medium

**Why:** IDOR on basket and address endpoints allows any authenticated user to read or modify another user's data by guessing integer IDs.

**How:**
1. In `routes/basket.ts`, after fetching the basket, verify `basket.UserId === loggedInUser.data.id`
2. Apply same ownership check in address routes
3. Use UUIDs instead of sequential integers for resource IDs where possible

```typescript
// Add to routes/basket.ts after basket retrieval
const basket = await BasketModel.findByPk(req.params.id, { include: ... })
if (!basket || basket.UserId !== loggedInUser.data.id) {
  return res.status(403).json({ error: 'Access denied' })
}
```

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html — CWE-639

---

### <a id="m-018"></a>M-018 · Add Authentication Middleware to PUT /api/Products/:id

**Addresses:** [T-020](#t-020)
**Priority:** <span style="background:#ca8a04;color:white;padding:1px 6px;border-radius:3px;font-size:0.85em">Medium</span> | **Effort:** Low

**Why:** The commented-out auth middleware at `server.ts:369` allows unauthenticated product modification.

**How:**
1. Uncomment (or re-add) the `security.isAuthorized()` middleware for `PUT /api/Products/:id` at `server.ts:369`
2. Additionally restrict to `isAccounting()` or `isAdmin` role since product management should be admin-only

```typescript
// Before (server.ts:369) — commented out
// app.put('/api/Products/:id', security.isAuthorized())

// After
app.put('/api/Products/:id', security.isAuthorized())
```

**Reference:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/ — CWE-862

---

## 11. Out of Scope

The following areas were not analyzed in this threat model:

- **Physical security:** Data center, hardware, and physical access controls
- **Third-party SaaS internals:** Google OAuth infrastructure, GitHub Actions runner security
- **Infrastructure outside the repository:** Cloud provider IAM, VPC configuration, DNS, CDN configuration (none configured by default)
- **Browser security beyond CSP:** Browser-specific vulnerabilities, extension attacks
- **Challenge solution documentation:** Individual challenge solutions in SOLUTIONS.md or the companion guide
- **Monitoring infrastructure:** Grafana dashboard configuration (`monitoring/grafana-dashboard.json`) was not analyzed
- **i18n/translation security:** Crowdin integration and translation file security
- **Web3/Blockchain features:** NFT minting, wallet exploit, and contract interaction endpoints were noted but not analyzed in depth
- **Intentional vs. unintentional vulnerabilities:** This analysis treats all confirmed vulnerabilities as security findings regardless of whether they are intentional training challenges, since the threat model serves as an educational reference
