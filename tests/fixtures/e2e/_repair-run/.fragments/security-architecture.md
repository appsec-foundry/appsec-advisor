## 7. Security Architecture

This chapter is organized by security-control category. The architecture section avoids artificial control IDs and finding-ID columns in overview tables. Findings are listed only where the affected control is described.

_§7 schema v2 (13-section control-category layout). Cataloged controls: 29 total — 1 adequate, 4 partial, 1 weak, 16 unsafe, 7 missing. Linked threats: 38._

**How to read the verdicts.** Every control category (and every sub-control below it) carries exactly one status. The two red verdicts do **not** mean the same thing — this is the distinction that decides what you have to do about a finding:

| Status | Meaning | What it asks of you |
|---|---|---|
| 🟢 Adequate | Control is present and sound | Nothing — keep it |
| 🟡 Partial | Present, but with meaningful gaps | Close the gap |
| 🟠 Weak | Present, but has exploitable gaps | Strengthen it |
| 🔴 Unsafe | **Present and relied upon, but defeated / trivially bypassable** | **Fix the existing control** |
| 🔴 Missing | **Control was never built** | **Add the control** |
| — | Not applicable to this codebase | — |

So "🔴 Unsafe" on a control category does *not* mean the control is absent — it means the control exists but does not hold (e.g. an MD5 password hash, a raw-SQL query path, a hardcoded signing key). "🔴 Missing" is reserved for controls that were never built (e.g. no Content-Security-Policy header).

### 7.1 Security Control Overview

<!-- §7.1 MECHANICAL-FROZEN — DO NOT EDIT (overview table is pregenerator-owned) -->

| Control category | Verdict | Main reason |
|---|---|---|
| [7.2 Identity and Authentication Controls](#72-identity-and-authentication-controls) | 🔴 Unsafe | 3 routed findings; catalogued controls are present but defeated (e.g. JWT signing key management, Login rate limiting). |
| [7.3 Session and Token Controls](#73-session-and-token-controls) | 🔴 Unsafe | 1 routed finding; catalogued controls are present but defeated (e.g. JWT token storage, JWT algorithm validation). |
| [7.4 Authorization Controls](#74-authorization-controls) | 🔴 Unsafe | 4 routed findings; catalogued controls are present but defeated (e.g. Server-side admin authorization, Product modification authorization). |
| [7.5 Query Construction and Data Access Controls](#75-query-construction-and-data-access-controls) | 🔴 Unsafe | 4 routed findings; catalogued controls are present but defeated (e.g. SQL parameterization, NoSQL query parameterization). |
| [7.6 Input Boundary Validation Controls](#76-input-boundary-validation-controls) | 🔴 Unsafe | 1 routed finding; catalogued controls are present but defeated (e.g. Server-side input validation). |
| [7.7 Output Encoding and Rendering Controls](#77-output-encoding-and-rendering-controls) | 🔴 Unsafe | 2 routed findings; catalogued controls are present but defeated (e.g. XSS output encoding). |
| [7.8 Browser and Cross-Origin Controls](#78-browser-and-cross-origin-controls) | 🔴 Unsafe | 3 routed findings; catalogued controls are present but defeated (e.g. CORS policy, Content Security Policy). |
| [7.9 Cryptography Secrets and Data Protection](#79-cryptography-secrets-and-data-protection) | 🔴 Unsafe | 3 routed findings; catalogued controls are present but defeated (e.g. Password hashing, Secret management). |
| [7.10 File Parser and Outbound Request Controls](#710-file-parser-and-outbound-request-controls) | 🔴 Unsafe | 10 routed findings; catalogued controls are present but defeated (e.g. XML parser hardening, ZIP upload path validation). |
| [7.11 Operations Runtime and Supply Chain Controls](#711-operations-runtime-and-supply-chain-controls) | 🔴 Unsafe | 3 routed findings; catalogued controls are present but defeated (e.g. Dependency security, Container image pinning). |
| [7.12 Real-time and Not Applicable Controls](#712-real-time-and-not-applicable-controls) | 🟡 Partial | 0 routed findings; 2 partial controls (e.g. WebSocket security, Rate limiting (general)) leave gaps. |
| [7.13 Defense-in-Depth Summary](#713-defense-in-depth-summary) | — | No controls or findings routed to this category. |

<!-- §7.1 MECHANICAL-FROZEN END -->

### 7.2 Identity and Authentication Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Password-Based Authentication](#password-based-authentication), [MFA / TOTP](#mfa-totp), [OAuth / OIDC Federated Login](#oauth-oidc-federated-login).

**Implemented controls:** JWT-based session tokens issued on every successful login, TOTP-based 2FA available as an optional user setting, OAuth login adapter via Google federated identity.

**Assessment:** Authentication boundaries are defeated at the key-management layer and the credential-verification layer simultaneously. The RSA private key for JWT signing is committed in `lib/insecurity.ts`; the `express-jwt` middleware also accepts `alg:none`, meaning tokens can be forged without the key at all. Password login queries the database through raw SQL string interpolation at `routes/login.ts:37`, which an attacker can short-circuit without a valid credential. Rate limiting on the login endpoint is absent. Each successful flow terminates in the server issuing a session token; the signing, validation, propagation, storage, and lifecycle of that token are described in [§7.3 Session and Token Controls](#73-session-and-token-controls).

<!-- §7.2 AUTH-MECHANISMS-FROZEN — deterministic inventory, pregenerator-owned. DO NOT EDIT. -->
**Authentication mechanisms (at a glance).** Every authentication mechanism detected on the application, its effective status, where it is assessed, and its linked findings. Controls are catalogued by domain, so JWT/session handling is assessed under [§7.3 Session and Token Controls](#73-session-and-token-controls) and password hashing under [§7.9 Cryptography Secrets and Data Protection](#79-cryptography-secrets-and-data-protection).

| Mechanism | Status | Assessed in | Findings |
|---|---|---|---|
| Password login | 🔴 Missing | [§7.2](#72-identity-and-authentication-controls) | — |
| Password storage (hashing) | 🔴 Unsafe | [§7.9](#79-cryptography-secrets-and-data-protection) | [F-007](#f-007) — MD5 password hashing trivially reversible lib/insecurity.ts<br/>[F-009](#f-009) — User passwords stored as unsalted MD5 data at rest models/user.ts |
| JWT / bearer-token session | 🔴 Unsafe | [§7.3](#73-session-and-token-controls) | [F-002](#f-002) — Hardcoded RSA private key enables JWT forgery lib/insecurity.ts<br/>[F-003](#f-003) — JWT algorithm none bypass via express jwt lib/insecurity.ts<br/>[F-021](#f-021) — JWT public key and premium.key exposed at /encryptionkeys server.ts<br/>[F-028](#f-028) — JWT stored in localStorage XSS accessible token storage login.component.ts |
| Session-token storage | 🔴 Unsafe | [§7.3](#73-session-and-token-controls) | [F-028](#f-028) — JWT stored in localStorage XSS accessible token storage login.component.ts |
| Multi-factor authentication (TOTP / 2FA) | 🟡 Partial | [§7.2](#72-identity-and-authentication-controls) | — |
| OAuth / OIDC federated login | 🟠 High | [§7.2](#72-identity-and-authentication-controls) | [F-027](#f-027) — OAuth token exposed in URL fragment oauth/oauth.component.ts |

_Also checked, not detected on this codebase: User registration, Password reset / change._

<!-- §7.2 AUTH-MECHANISMS-FROZEN END -->

<a id="password-based-authentication"></a>
#### 7.2.1 Password-Based Authentication

**Status:** 🔴 Unsafe — credential verification is bypassable via SQL injection and brute-force is unconstrained by the absence of rate limiting.

Password-based authentication covers login and registration. In Juice Shop, login is handled at `POST /rest/user/login` (`routes/login.ts`) and registration at `POST /api/Users`. Two weaknesses defeat this mechanism simultaneously:

- **SQL injection bypass:** `routes/login.ts:37` builds the credential query via string interpolation; an attacker can submit a crafted email to bypass credential verification entirely. Assessed in detail in [§7.5 Query Construction and Data Access Controls](#75-query-construction-and-data-access-controls).
- **No rate limiting:** `server.ts` mounts the login route with no `express-rate-limit` or equivalent middleware; brute-force attempts are unconstrained.

The normal password login flow, and the brute-force abuse path in its current state, are shown below:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant API as Express API (routes/login.ts)
    participant DB as SQLite via Sequelize

    User->>API: POST /rest/user/login (email, password)
    API->>DB: Query with email and MD5 password (string interpolated)
    DB-->>API: User record if credentials match
    API-->>User: 200 OK with RS256 JWT

    alt Current state — no rate limiting
        User->>API: POST /rest/user/login (repeated brute-force attempts)
        API-->>User: 200 OK or 401 — no throttle enforced
    else After mitigation
        User->>API: POST /rest/user/login (attempt after threshold)
        API-->>User: 429 Too Many Requests — rate limit applied
    end
```

**Security assessment**

The login route at `routes/login.ts:37` constructs the SQL query via string interpolation, enabling credential bypass via SQL injection (see [§7.5](#75-query-construction-and-data-access-controls)). Additionally, `server.ts` mounts the login route with no rate-limit middleware, enabling unbounded brute-force against any account. Password storage uses unsalted MD5 (assessed in [§7.9 Cryptography Secrets and Data Protection](#79-cryptography-secrets-and-data-protection)), which means any hash dump is immediately reversible offline.

**Relevant findings**

- [F-030](#f-030) — no rate limiting on the login endpoint allows unbounded brute-force attempts.

<a id="mfa-totp"></a>
#### 7.2.2 MFA / TOTP

**Status:** 🟡 Partial — TOTP enrollment and verification are implemented but 2FA is optional and not enforced for privileged accounts.

Two-factor authentication reduces account-takeover risk by requiring a time-based one-time passcode in addition to the password. Juice Shop implements TOTP enrollment via `speakeasy` and QR-code display; users can enroll voluntarily through the profile settings page. Admin accounts and the default seeded admin user are not required to enroll. Because JWT forgery ([F-002](#f-002), [F-003](#f-003)) bypasses the login flow entirely, 2FA provides no residual protection when those findings are exploited.

The TOTP verification flow for enrolled users is shown below:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant API as Express API
    participant TOTP as TOTP Verifier (speakeasy)

    User->>API: POST /rest/user/login with email and password
    API-->>User: 401 with TOTP challenge (if enrolled)
    User->>API: POST /rest/2fa/verify with TOTP code
    API->>TOTP: Verify code against stored secret
    TOTP-->>API: Valid or invalid
    API-->>User: 200 OK with JWT (valid) or 401 (invalid)
```

**Security assessment**

TOTP enrollment and server-side verification work correctly for enrolled users. The gap is enforcement scope: admin accounts and the default seeded admin user are not required to enroll. Since JWT forgery ([F-002](#f-002), [F-003](#f-003)) bypasses the entire login flow including the TOTP challenge, 2FA provides no residual protection against an attacker who exploits those findings. The control is architecturally sound but strategically ineffective given the JWT forgery weaknesses assessed in [§7.3 Session and Token Controls](#73-session-and-token-controls).

**Relevant findings**

- [F-002](#f-002) — JWT forgery bypasses the TOTP challenge entirely; 2FA protection depends on this being fixed first.
- [F-003](#f-003) — algorithm `none` bypass also sidesteps TOTP verification.

<a id="oauth-oidc-federated-login"></a>
#### 7.2.3 OAuth / OIDC Federated Login

**Status:** 🟠 Weak — the OAuth adapter is present but leaks the access token in the URL fragment, exposing it to browser history and Referer headers.

Juice Shop implements a Google OAuth login adapter in `oauth/oauth.component.ts`. On successful Google authentication, the adapter receives an access token via the implicit grant flow and uses it to obtain a Juice Shop session JWT. The current implementation uses `response_type=token`, which causes Google to append the access token to the redirect URL as a fragment parameter rather than returning an authorization code.

The OAuth login flow showing the current token exposure is shown below:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser
    participant API as Express API
    participant Google as Google OAuth

    User->>Browser: Click "Login with Google"
    Browser->>Google: GET /oauth/authorize (response_type=token)
    Google-->>Browser: Redirect to callback with token in URL fragment
    Note over Browser: Token visible in address bar, browser history, Referer logs
    Browser->>API: POST /rest/user/login with access token
    API-->>User: 200 OK with Juice Shop JWT

    alt After mitigation
        Browser->>Google: GET /oauth/authorize (response_type=code, PKCE)
        Google-->>Browser: Redirect to callback with authorization code
        Browser->>API: POST with code — token never appears in URL
        API-->>User: 200 OK with Juice Shop JWT
    end
```

**Security assessment**

The implicit grant flow (`response_type=token`) causes the OAuth access token to appear in the URL fragment. This exposes it to: browser history (readable by any same-origin JavaScript, including via XSS), HTTP Referer headers on subsequent navigation, and server access logs that record full request URIs. The fix is to migrate to the authorization code flow with PKCE (`response_type=code`), which exchanges a short-lived code server-side and keeps the access token out of the URL entirely.

**Relevant findings**

- [F-027](#f-027) — OAuth access token exposed in URL fragment via implicit grant flow in `oauth/oauth.component.ts`.

### 7.3 Session and Token Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [JWT signing key management](#jwt-signing-key-management), [JWT token storage](#jwt-token-storage), [JWT algorithm validation](#jwt-algorithm-validation).

**Implemented controls:** RS256-signed JWTs issued on login, `express-jwt` middleware protecting authenticated routes, token transmitted as `Authorization: Bearer` header on every API request.

**Assessment:** This application uses a single locally-signed token format (commonly called JWT) for every authenticated session, regardless of the login flow in §7.2 that established it. The sub-sections below trace one token through its lifecycle: signing on issuance (assessed below in [JWT signing key management](#jwt-signing-key-management)), validation on every protected request, storage in the browser, manual revocation, and time-based expiry. Token storage in `localStorage` makes the session readable by any JavaScript running in the page, meaning any XSS finding ([F-018](#f-018), [F-037](#f-037)) can harvest the session token. Algorithm validation is the second critical gap: the middleware does not restrict the accepted algorithm set, allowing unsigned tokens.

<a id="jwt-signing-key-management"></a>
#### 7.3.1 JWT signing key management

**Status:** 🔴 Unsafe — the RSA private key used to sign session tokens is committed in source and the matching public key is served unauthenticated, so any reader can forge tokens.

JWT signing binds each issued session token to a server-held RSA private key; every authenticated route depends on this secret staying private. `lib/insecurity.ts` exposes the key pair via `exports.privateKey` and `exports.publicKey`, which the `express-jwt` middleware loads at startup.

**Security assessment**

The RSA private key (`-----BEGIN RSA PRIVATE KEY-----…`) is committed at `lib/insecurity.ts:26-28`. Any reader of the public repository can call `jwt.sign(payload, privateKey, {algorithm: 'RS256'})` to mint a token carrying arbitrary `role` claims (including `admin`) that is accepted by every protected route. The matching public key is additionally served at `/encryptionkeys`, confirming the key material is intentionally — but insecurely — reachable. Compromise here is permanent: rotation requires a code change and redeploy, and every historically-issued token remains forgeable from the committed key. The independent algorithm-confusion bypass is assessed in [§7.3.3 JWT algorithm validation](#jwt-algorithm-validation).

**Relevant findings**

- [F-002](#f-002) — hardcoded RSA private key means any code-repo reader can forge a valid signed JWT.
- [F-021](#f-021) — the public key is also served at `/encryptionkeys`, confirming the key material is intentionally accessible.

<a id="jwt-token-storage"></a>
#### 7.3.2 JWT token storage

**Status:** 🔴 Unsafe — the token is written to `localStorage`, which is accessible to any same-origin JavaScript execution.

After a successful login, `login.component.ts` stores the JWT in `localStorage` under the key `token`. Subsequent Angular service calls retrieve it from there and attach it as the `Authorization` header for every API request.

**Security assessment**

`localStorage` has no `HttpOnly` or `SameSite` equivalents — any JavaScript running in the same origin (including via XSS) can read `localStorage.getItem('token')` and send it to an external endpoint. The DOM XSS sink in search results ([F-018](#f-018)) and the stored XSS via `bypassSecurityTrustHtml` ([F-037](#f-037)) both provide an attacker with JavaScript execution in the origin, making `localStorage` token storage the direct escalation path from script injection to session hijack. Storing the token in an `HttpOnly` cookie would eliminate this escalation channel.

**Relevant findings**

- [F-028](#f-028) — JWT stored in `localStorage` is accessible to any cross-site script that achieves JavaScript execution in the origin.

<a id="jwt-algorithm-validation"></a>
#### 7.3.3 JWT algorithm validation

**Status:** 🔴 Unsafe — the `express-jwt` middleware does not restrict the accepted algorithm set; tokens with `alg:none` pass signature verification.

Every request to a protected API route passes through `express-jwt` middleware, which decodes and verifies the `Authorization: Bearer` token. The middleware is configured in `lib/insecurity.ts` and mounted globally for authenticated routes in `server.ts`.

**Security assessment**

The `express-jwt` configuration omits the `algorithms` option, which means the library falls back to accepting any algorithm the token header names — including `none`. A request with a hand-crafted JWT carrying `{"alg":"none","typ":"JWT"}` and any payload (including `{"role":"admin"}`) passes the middleware check without a cryptographic signature. This finding is independent of the committed private key ([F-002](#f-002)): even after the key is rotated, the algorithm whitelist must also be added, or the control remains bypassed.

**Relevant findings**

- [F-003](#f-003) — algorithm `none` acceptance makes the RS256 signing control irrelevant; tokens require no key.
- [F-002](#f-002) — complementary path: even with a valid algorithm header, the committed private key allows forgery with a real signature.

### 7.4 Authorization Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Server-side admin authorization](#server-side-admin-authorization), [Product modification authorization](#product-modification-authorization), [CSRF protection](#csrf-protection).

**Implemented controls:** Angular route guard (`app.guard.ts`) checks `localStorage` for a valid token before rendering admin views, JWT `role` claim present in issued tokens.

**Assessment:** Authorization enforcement is split between an Angular client-side guard (which has no server-side counterpart for admin routes) and the absence of any ownership check on product modification. The CSRF control was never built. Any attacker who bypasses authentication ([F-002](#f-002), [F-001](#f-001)) or who is already an authenticated user can reach admin API routes and arbitrary product records.

<a id="server-side-admin-authorization"></a>
#### 7.4.1 Server-side admin authorization

**Status:** 🔴 Unsafe — `app.guard.ts` is the only enforcement point; admin API routes have no server-side role check.

Admin-facing pages in the Angular SPA are gated by `app.guard.ts`, which reads the JWT from `localStorage`, decodes the `role` claim client-side, and redirects non-admin users away from the administration component. Express routes that service admin actions rely on the same JWT middleware used for all authenticated routes, but add no additional role check.

**Security assessment**

Client-side guards are a UX convenience, not a security boundary. Because the JWT `role` field can be forged via [F-002](#f-002) or [F-003](#f-003), and because Express routes for admin operations (product management, user listing) lack a middleware step that checks `req.user.role === 'admin'`, any authenticated user with a tampered token reaches admin endpoints directly. The user-enumeration endpoint at `GET /api/Users` ([F-019](#f-019)) is an example: it returns all user records with no role check beyond authentication.

**Relevant findings**

- [F-038](#f-038) — Angular admin route guard is the sole enforcement point; bypassed by token forgery or direct API call.
- [F-019](#f-019) — `/api/Users` returns all user records to any authenticated request regardless of role.
- [F-033](#f-033) — B2B API at `/b2b/v2` is reachable by any authenticated user.

<a id="product-modification-authorization"></a>
#### 7.4.2 Product modification authorization

**Status:** 🔴 Unsafe — `PUT /api/Products/:id` accepts modifications from any request, including unauthenticated ones.

Product data is managed through the Sequelize-generated REST API (`/api/Products`). Read access is public; write access via `PUT /api/Products/:id` is served by the same route without an authentication or ownership middleware step. `server.ts` mounts the endpoint without wrapping it in the JWT verification middleware.

**Security assessment**

`PUT /api/Products/:id` processes any well-formed request body with no authentication check. Any client — including unauthenticated scrapers — can overwrite product name, description, price, or image URL for any product in the catalogue. Combined with the stored XSS sink ([F-037](#f-037)), this path allows an attacker to inject a malicious `<script>` into a product description that is subsequently rendered in every admin's browser via `bypassSecurityTrustHtml`.

**Relevant findings**

- [F-013](#f-013) — `PUT /api/Products/:id` has no authentication check; any caller can modify any product.
- [F-037](#f-037) — unauthenticated product modification enables stored XSS payload delivery to the admin panel.

<a id="csrf-protection"></a>
#### 7.4.3 CSRF protection

**Status:** 🔴 Missing — no CSRF token or SameSite cookie constraint exists on any state-changing endpoint.

CSRF protection ensures that state-changing requests (order placement, profile update, password change) originate from the application's own pages rather than from attacker-controlled cross-origin pages. The standard implementation requires either a synchronised token in the request body or a `SameSite=Strict` cookie binding.

**Security assessment**

`server.ts` mounts no `csurf` or equivalent middleware. Session credentials are stored in `localStorage` and transmitted via `Authorization` header rather than a cookie, which eliminates the classic CSRF cookie-theft vector but does not protect against cross-origin `fetch()` calls when CORS is configured with a wildcard origin ([F-016](#f-016)). With `Access-Control-Allow-Origin: *`, a page on any domain can make credentialed API requests using a token the victim's browser holds, achieving the same result as a classic CSRF attack.

**Relevant findings**

- [F-015](#f-015) — no CSRF protection on any state-changing endpoint.
- [F-016](#f-016) — wildcard CORS amplifies the CSRF gap by permitting cross-origin API calls from any domain.

### 7.5 Query Construction and Data Access Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [SQL parameterization](#sql-parameterization), [NoSQL query parameterization](#nosql-query-parameterization).

**Implemented controls:** Sequelize ORM present and used for most model operations; MarsDB handles product-review data.

**Assessment:** The ORM is available but explicitly bypassed on the two highest-traffic attack surfaces: login and product search. Both call `models.sequelize.query()` with template literals. MarsDB review paths pass request body fields directly into the query selector, enabling operator injection. The same structural decision — raw string composition instead of parameterisation — appears independently on unrelated routes, indicating a codebase-wide pattern rather than a single regression.

<a id="sql-parameterization"></a>
#### 7.5.1 SQL parameterization

**Status:** 🔴 Unsafe — login and product-search routes bypass the ORM and interpolate user input into raw SQL strings.

Sequelize backs the majority of relational data access, and most model `find*` and `create` calls use its built-in parameter binding. The login route (`routes/login.ts`) and the product-search route (`routes/search.ts`) each call `models.sequelize.query()` directly with a template literal that splices `req.body` fields into the query string.

The login route shows the raw SQL interpolation pattern:

```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}'
   AND password = '${security.hash(req.body.password || '')}'
   AND deletedAt IS NULL`
)
```

**Security assessment**

Both raw-SQL paths accept attacker-controlled input without binding. On the login route, the payload `' OR '1'='1'--` short-circuits the WHERE clause and returns the first row (the seeded admin), bypassing authentication entirely. On the search route, a UNION payload allows cross-table exfiltration of arbitrary SQLite data. Neither route reaches the ORM's `replacements` / `bind` path.

**Relevant findings**

- [F-001](#f-001) — SQL injection in `routes/login.ts:37` enables authentication bypass returning the admin row.
- [F-005](#f-005) — SQL injection in the product-search route enables UNION-based data exfiltration.
- [F-017](#f-017) — NoSQL injection in the review-update route exploits the same absence of parameterisation in a different data store.

<a id="nosql-query-parameterization"></a>
#### 7.5.2 NoSQL query parameterization

**Status:** 🔴 Unsafe — MarsDB review routes accept user-controlled fields as query selector properties, enabling operator injection.

Product reviews are stored in MarsDB and queried via `updateProductReviews.ts` and `showProductReviews.ts`. Both files extract fields from `req.body` or `req.params` and pass them directly as MarsDB selector objects.

**Security assessment**

`updateProductReviews.ts` passes `req.body.id` directly as the `_id` selector value without asserting it is a scalar string. Sending `{"id": {"$gt": ""}}` matches every review document, letting an authenticated user overwrite reviews they did not author. `showProductReviews.ts` exposes a `$where` operator path that evaluates a JavaScript expression server-side inside MarsDB. Combined, the two routes allow horizontal privilege escalation across review ownership and JavaScript-expression injection within the DB context.

**Relevant findings**

- [F-017](#f-017) — NoSQL injection in review update allows modification of any review by any authenticated user.
- [F-025](#f-025) — `$where` operator injection in product-review listing evaluates attacker-controlled JavaScript inside MarsDB.

### 7.6 Input Boundary Validation Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Validation Approach](#validation-approach), [Server-side input validation](#server-side-input-validation).

**Implemented controls:** `multer` enforces a file-size limit on upload routes; `express-validator` library is present in the dependency tree.

**Assessment:** File-size limits on uploads represent a narrow defensive surface. Request-body schema validation is absent on injection-prone routes; the `express-validator` library is available but not applied at the login, search, or review endpoints.

<a id="validation-approach"></a>
#### 7.6.1 Validation Approach

**Status:** 🟡 Partial — file-size limits are enforced by `multer`; request-body schema validation is absent on injection-prone routes.

`multer` middleware is configured on file-upload routes with a maximum file size. Express routes accept arbitrary JSON body payloads through `body-parser` without schema or type constraints.

**Security assessment**

The file-size limit prevents upload-based DoS from oversized files but does not constrain the structure or content of request body fields. JSON fields on login, search, and review endpoints arrive with no type assertion; an object where a string is expected (e.g. `{"email": {"$gt": ""}}`) reaches downstream query construction unchecked. Adding `express-validator` or `ajv` schema enforcement at the route level would eliminate the structural precondition for both SQL and NoSQL injection.

**Relevant findings**

- [F-029](#f-029) — B2B infinite-loop DoS arises partly from absent input-size and structure validation on the order-lines field.

<a id="server-side-input-validation"></a>
#### 7.6.2 Server-side input validation

**Status:** 🔴 Unsafe — untrusted request fields reach SQL and NoSQL query constructors without type checking or schema enforcement.

Express routes receive JSON bodies via `body-parser`. Most routes destructure fields from `req.body` and pass them directly to query or rendering layers without checking that scalar fields are actually scalars.

**Security assessment**

The absence of type assertions at route entry points is the structural root of the injection findings in §7.5 and the eval-injection finding in §7.10. Adding a strict JSON schema validator at the route middleware level — asserting that `email` is a string, `id` is a non-negative integer, `orderLinesData` is a valid JSON array — would raise the exploitation bar for injection attempts without requiring changes to the downstream query or rendering code.

**Relevant findings**

- [F-029](#f-029) — B2B endpoint accepts an `orderLinesData` value of arbitrary depth and structure, enabling infinite-loop DoS and sandbox escape.

### 7.7 Output Encoding and Rendering Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [XSS output encoding](#xss-output-encoding).

**Implemented controls:** Angular template binding (`{{ }}` interpolation) encodes output by default; Helmet `xssFilter` header set.

**Assessment:** Default Angular template encoding applies to the majority of the SPA. Six components explicitly defeat it by calling `bypassSecurityTrustHtml()` on user-supplied content. The search-result component renders URL query parameters into the DOM via an unsafe binding. Helmet's `xssFilter` header targets the now-deprecated IE XSS Auditor and provides no protection against either class of XSS in modern browsers; it is not a substitute for a Content-Security-Policy.

<a id="xss-output-encoding"></a>
#### 7.7.1 XSS output encoding

**Status:** 🔴 Unsafe — `bypassSecurityTrustHtml()` is called on user-controlled content in multiple Angular components, and search results render query parameters into the DOM without sanitisation.

Angular's `DomSanitizer.bypassSecurityTrustHtml()` marks a value as pre-approved HTML, suppressing the default output-encoding that Angular applies to `[innerHTML]` bindings. `administration.component.ts` uses this path to render product-description content stored in the database. The search-result component interpolates the `q` query parameter directly into a DOM element.

The stored XSS path through the admin component is shown below:

```ts
// administration.component.ts
this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(product.description)
// template: <div [innerHTML]="trustedHtml"></div>
```

**Security assessment**

`bypassSecurityTrustHtml()` calls appear in six component files. Each call site where the input originates from user-supplied data (product descriptions, review content, search terms) is a stored or reflected XSS sink. Combined with `localStorage` JWT storage ([F-028](#f-028)), any XSS execution that reads `localStorage.getItem('token')` and exfiltrates it completes a session-hijack chain. A Content-Security-Policy restricting `script-src` would reduce this blast radius even where `bypassSecurityTrustHtml()` calls remain.

**Relevant findings**

- [F-037](#f-037) — stored XSS via `bypassSecurityTrustHtml()` in `administration.component.ts` executes in admin sessions.
- [F-018](#f-018) — DOM XSS in search-result component renders the `q` parameter as raw HTML in the browser.

### 7.8 Browser and Cross-Origin Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [CORS policy](#cors-policy), [Content Security Policy](#content-security-policy).

**Implemented controls:** Helmet middleware sets `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, and `X-XSS-Protection: 0`. CORS middleware is mounted in `server.ts`.

**Assessment:** Helmet's baseline security headers (noSniff, frameguard) are active. CORS is configured but uses a wildcard origin for most endpoints, which nullifies the same-origin policy for API calls. Content-Security-Policy is absent, leaving the browser with no instruction to restrict script sources and no backstop against the XSS sinks in §7.7.

<a id="cors-policy"></a>
#### 7.8.1 CORS policy

**Status:** 🔴 Unsafe — `Access-Control-Allow-Origin: *` is set globally, allowing any origin to read API responses.

The `cors()` middleware in `server.ts` is applied to all routes without an `origin` allowlist. This emits `Access-Control-Allow-Origin: *` on every response, including routes that return authenticated user data.

The CORS interaction with authenticated routes is shown below:

```ts
// server.ts — wildcard CORS applied before route registration
app.use(cors())
app.use('/rest/user/whoami', /* authenticated route */ )
```

**Security assessment**

A wildcard CORS policy allows any web page to send a cross-origin `fetch()` to the API and read the response. When combined with the `Authorization` header pattern (rather than cookies), the standard CSRF mitigation of `SameSite` cookies does not apply; an attacker page can induce a victim's browser to call the API using the victim's stored JWT from a phishing or injected page. The `/api/Users` endpoint ([F-019](#f-019)) and user basket data are reachable under this policy.

**Relevant findings**

- [F-016](#f-016) — wildcard CORS on sensitive API endpoints exposes user data to any cross-origin request.
- [F-015](#f-015) — absence of CSRF tokens is amplified by wildcard CORS permitting cross-origin state-changing calls.
- [F-035](#f-035) — missing CSP leaves the browser with no script-source restriction to compensate for the open CORS policy.

<a id="content-security-policy"></a>
#### 7.8.2 Content Security Policy

**Status:** 🔴 Missing — no `Content-Security-Policy` header is set; the browser has no instruction to restrict script execution sources.

A Content-Security-Policy instructs the browser to execute scripts only from approved origins, blocking inline script execution and unauthorised external script loading. `server.ts` configures Helmet but does not call `helmet.contentSecurityPolicy()`.

**Security assessment**

Without a CSP, every XSS sink in §7.7 has the full JavaScript execution environment available to it: access to `localStorage`, cross-origin `fetch()` via the wildcard CORS policy, and DOM manipulation. A `script-src 'self'` policy would prevent the majority of practical XSS exploitation even when an injection sink exists. The CSP is also the last-resort control that would reduce the blast radius of `bypassSecurityTrustHtml()` calls that cannot be immediately removed.

**Relevant findings**

- [F-035](#f-035) — missing CSP means no browser-side constraint on script execution sources backs up the XSS sinks in §7.7.
- [F-016](#f-016) — wildcard CORS and absent CSP together allow unrestricted cross-origin exfiltration from XSS execution contexts.

### 7.9 Cryptography Secrets and Data Protection

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Password Hashing and Credential Storage](#password-hashing-and-credential-storage), [Secret management](#secret-management), [Data encryption at rest](#data-encryption-at-rest).

**Implemented controls:** RS256 algorithm chosen for JWT signing (key material committed); Sequelize model defines the `password` column; SQLite database file written to the container filesystem.

**Assessment:** Cryptographic algorithm choices are correct at the surface level (RS256 vs HS256; a hash function vs plain text), but every secret is hardcoded in source and every hash uses an algorithm (MD5, unsalted) that has been trivially reversible for over a decade. The database file is written unencrypted to a writable container path. There is no mechanism that keeps secrets out of the repository.

<a id="password-hashing"></a><a id="password-hashing-and-credential-storage"></a>
#### 7.9.1 Password Hashing and Credential Storage

**Status:** 🔴 Unsafe — passwords are hashed with unsalted MD5; every stored hash is crackable in seconds with a rainbow table.

`lib/insecurity.ts` exports a `hash()` function used by both the registration flow and the login query to derive the stored credential. The Sequelize `User` model stores the result in the `password` column as a hex string.

The hash function used is:

```ts
// lib/insecurity.ts
exports.hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

**Security assessment**

MD5 produces a 128-bit digest and has no salt parameter. Two users with the same password produce identical hashes, and precomputed rainbow tables cover the entire common-password space. Any read of the `password` column — via SQL injection, the exposed SQLite file ([F-024](#f-024)), or the hardcoded admin credentials — yields hashes that are reversible in milliseconds. Replacing with `bcrypt` (cost factor ≥ 12) or `argon2id` with a random per-user salt would eliminate offline cracking viability.

**Relevant findings**

- [F-007](#f-007) — MD5 hash function in `lib/insecurity.ts` is trivially reversible; no salt prevents rainbow-table attacks.
- [F-009](#f-009) — the SQLite `Users` table stores every password as an unsalted MD5 hex string at rest.

<a id="secret-management"></a>
#### 7.9.2 Secret management

**Status:** 🔴 Unsafe — RSA private key, HMAC secret, and admin password are committed verbatim in source files that are part of the public repository.

`lib/insecurity.ts` declares the RSA private key and public key as multi-line string literals at lines 1–28. The same file exports the HMAC secret used for coupon generation. The seeded admin password hash is stored in `data/static/users.yml`. None of these values are injected at runtime from environment variables or a secrets manager.

**Security assessment**

Three independent secrets are committed in three source files:

- RSA private key at `lib/insecurity.ts:1` — used to sign all session JWTs.
- HMAC secret at `lib/insecurity.ts` (exported as `exports.hmacKey`) — used by the coupon-generation route.
- Admin password hash in `data/static/users.yml` — seeded into the database on first startup.

Because the repository is public, all three are effectively public knowledge. Rotating requires a code change plus a redeploy; there is no environment-variable path. The exposed `/encryptionkeys` endpoint ([F-021](#f-021)) additionally serves the public key (and `premium.key`) over HTTP, reducing the work needed to verify a forged token.

**Relevant findings**

- [F-002](#f-002) — RSA private key committed in `lib/insecurity.ts` is available to any repository reader.
- [F-014](#f-014) — HMAC secret committed in `lib/insecurity.ts` allows arbitrary coupon forgery.
- [F-004](#f-004) — admin credentials seeded from `data/static/users.yml`; the hash is pre-image-attackable given MD5.

<a id="data-encryption-at-rest"></a>
#### 7.9.3 Data encryption at rest

**Status:** 🔴 Missing — the SQLite database file is written unencrypted to a writable container filesystem path.

Sequelize uses SQLite as its backing store. The database file (`data/juiceshop.sqlite`) is created on the container's writable layer when the application starts. No SQLite encryption extension (e.g. SQLCipher) is configured; the file is a standard unencrypted SQLite binary.

**Security assessment**

A container breakout, a misconfigured volume mount, or host-level read access to the container filesystem exposes the full database — all user records with MD5 password hashes, all orders, all personal data — without requiring any application-layer authentication. The combination of an unencrypted file and a trivially crackable hash format ([F-007](#f-007), [F-009](#f-009)) means a single file-copy operation yields every user credential in crackable form. Encrypting the database file would not substitute for replacing MD5, but it would raise the bar for persistence-layer attacks.

**Relevant findings**

- [F-024](#f-024) — SQLite database on the writable container filesystem with no encryption; full data exposure via container access.
- [F-007](#f-007) — unsalted MD5 hashes stored in the database make file-level access immediately actionable.

### 7.10 File Parser and Outbound Request Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [XML parser hardening](#xml-parser-hardening), [ZIP upload path validation](#zip-upload-path-validation), [SSRF prevention](#ssrf-prevention).

**Implemented controls:** `multer` enforces a file-size limit; `libxmljs2` is the XML parser; `unzipper` handles ZIP extraction; `express-validator` is available but unused on these routes.

**Assessment:** The file-handling surface concentrates the most Critical findings in the model. The XML parser runs with `noent:true` (external entity resolution enabled), the ZIP extractor writes entries using their embedded path without containment checks, and the profile-image-URL route passes user-supplied URLs to `fetch()` without host-allowlist validation. Three structurally independent control failures coexist on the same upload handler.

<a id="xml-parser-hardening"></a>
#### 7.10.1 XML parser hardening

**Status:** 🔴 Unsafe — `libxmljs2` is configured with `noent:true`, enabling external entity resolution (XXE).

`routes/fileUpload.ts` accepts XML files in the complaint submission flow. XML content is parsed using `libxmljs2.parseXmlString()` with the `noent` option set to `true`. The route also processes XML without a size-based complexity limit, leaving a document-expansion (billion-laughs) path open.

The vulnerable parser call is:

```ts
// routes/fileUpload.ts
libxmljs.parseXmlString(xmlString, { noent: true, noblanks: true })
```

**Security assessment**

With `noent:true`, an attacker can include `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in the uploaded XML and the parser will resolve it, embedding the file contents in the parsed output that the application then processes. On the container the application runs as a non-root user, but `/etc/passwd`, `/proc/self/environ` (containing environment variables including any injected secrets), and the SQLite file at `data/juiceshop.sqlite` are all readable. The billion-laughs variant ([F-031](#f-031)) uses deeply nested entity expansion to exhaust memory without external network access.

**Relevant findings**

- [F-010](#f-010) — XXE via XML upload; `noent:true` allows server-filesystem file-read via external entity reference.
- [F-031](#f-031) — billion-laughs DoS via deeply nested entity expansion in the same XML parser call.
- [F-036](#f-036) — ZIP path traversal is a parallel issue on the same upload route handler.

<a id="zip-upload-path-validation"></a>
#### 7.10.2 ZIP upload path validation

**Status:** 🔴 Unsafe — ZIP entries are extracted to disk using their embedded relative paths without a containment check; a `../` prefix allows traversal outside the upload directory.

`routes/fileUpload.ts` also handles ZIP file uploads. Entries are extracted using the `unzipper` library, which pipes each entry's stream directly to `fs.createWriteStream(entry.path)` where `entry.path` is the path stored in the ZIP central directory.

**Security assessment**

A ZIP archive with an entry named `../../server.ts` (or any path that resolves outside the intended upload directory) writes that entry's contents to the constructed path on the container filesystem. A write to a loaded module file triggers execution on the next `require()` call in a development context; even in production, overwriting static assets or configuration files reachable via the HTTP server has direct impact. No call to `path.resolve()` with a prefix check exists in the extraction loop.

**Relevant findings**

- [F-036](#f-036) — directory traversal in ZIP extraction allows writes outside the upload directory.
- [F-010](#f-010) — XML XXE on the same route handler represents a second read/write vector at the same endpoint.

<a id="ssrf-prevention"></a>
#### 7.10.3 SSRF prevention

**Status:** 🔴 Missing — the profile-image-URL upload route passes user-supplied URLs to `fetch()` without host-allowlist validation.

`routes/profileImageUrlUpload.ts` accepts a URL in the request body, calls `fetch(url)` server-side to retrieve the image, and stores the result as the user's profile image. No validation of the URL scheme, host, or IP range is performed before the fetch.

**Security assessment**

An attacker submits a URL pointing to an internal network endpoint (`http://169.254.169.254/latest/meta-data/` for cloud IMDS, or internal services on `10.0.0.0/8`) and the server fetches it on their behalf. The response body is returned in the server's log or reflected in error messages, enabling internal network reconnaissance. On a cloud-hosted deployment, this path can yield instance-metadata credentials. A scheme-and-host allowlist (only `https://` to external resolved IPs, denying RFC-1918 ranges) would close the path without removing the feature.

**Relevant findings**

- [F-026](#f-026) — SSRF via profile image URL; server fetches arbitrary URLs submitted in the profile-update request body.
- [F-006](#f-006) — FTP directory listing exposes confidential files to the same class of unauthenticated access as SSRF reconnaissance.

### 7.11 Operations Runtime and Supply Chain Controls

**Verdict:** 🔴 Unsafe

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Dependency security](#dependency-security), [Container image pinning](#container-image-pinning), [CI/CD security scanning](#cicd-security-scanning), [Sensitive file exposure](#sensitive-file-exposure), [Automated SCA scanning](#automated-sca-scanning), [Automated dependency updates](#automated-dependency-updates), [Lockfile hygiene](#lockfile-hygiene).

**Implemented controls:** `package-lock.json` present; Dependabot configuration file exists; GitHub Actions CI pipeline runs unit and integration tests; Docker image uses a specific tag (not `latest`).

**Assessment:** The operations surface has pockets of good practice (lockfile committed, Dependabot configured, CI pipeline active) that are undermined by deliberate suppression of security updates and missing least-privilege controls. `.dependabot/config.yml` sets `auto-merged: false` and `ignore` rules that block security-update branches for several packages. GitHub Actions workflows lack `permissions: read-all` scoping. The FTP directory and `/support/logs` endpoints serve sensitive files to unauthenticated HTTP requests.

<a id="dependency-security"></a>
#### 7.11.1 Dependency security

**Status:** 🔴 Unsafe — Dependabot is configured to suppress security updates for several packages; known-vulnerable library versions remain in the dependency tree.

`.dependabot/config.yml` defines `ignore` rules that prevent Dependabot from raising PRs for specific package ranges. The file's `auto-merged: false` setting combined with the ignore list means security updates for affected packages require manual intervention that the ignore rules themselves discourage.

**Security assessment**

The ignore rules in `.dependabot/config.yml` target packages that have known-bad versions with exploitable CVEs in the assessment window. Packages like `express-jwt` at the pinned version have public exploits; Dependabot is configured in a way that suppresses rather than surfaces the upgrade path. The `.dependabot` configuration is intentional (it is part of the Juice Shop challenge design), but in a real codebase this pattern leaves known-exploitable versions in production indefinitely.

**Relevant findings**

- [F-034](#f-034) — Dependabot update pinning suppresses security updates for vulnerable packages.
- [F-032](#f-032) — GitHub Actions workflow permissions allow excessive token scope.

<a id="container-image-pinning"></a>
#### 7.11.2 Container image pinning

**Status:** 🟠 Weak — the Docker base image uses a version tag but not a digest pin; image content can change without a Dockerfile change.

The Dockerfile specifies the Node base image by a version tag (e.g. `node:18-alpine`). Tag-based references are mutable: a registry operator can push a new image under the same tag. Digest pinning (`FROM node:18-alpine@sha256:…`) binds the build to a specific immutable image manifest.

**Security assessment**

Tag pinning is better than `latest` but not equivalent to digest pinning for supply-chain integrity. A compromised upstream registry or a deliberate tag overwrite (e.g. a patched CVE in the base image that changes its security posture) updates all builds that pull by tag without any change to the source tree. For a project with an active CI pipeline, digest pinning is a low-effort improvement with no operational cost.

**Relevant findings**

- [F-032](#f-032) — GitHub Actions permissions gap; combined with tag-based image pinning, CI/CD supply-chain integrity depends on third-party registry trust.

<a id="cicd-security-scanning"></a>
#### 7.11.3 CI/CD security scanning

**Status:** 🟡 Partial — the CI pipeline runs unit and integration tests but no SAST, secret-scanning, or SCA step exists in the workflow files.

`.github/workflows/ci.yml` runs `npm test` and `npm run frisby` on push and pull-request events. The pipeline produces test coverage results and fails on test failures.

**Security assessment**

CI gates on functional correctness but not on security regressions. No `npm audit` step, no secret-scanning action (e.g. `gitleaks` or `truffleHog`), and no SAST scan (e.g. `semgrep` or `eslint-plugin-security`) run in the pipeline. Adding `npm audit --audit-level=high` to the test step would surface the known-vulnerable packages flagged in [F-034](#f-034) on every build. The GitHub Actions workflow also uses default permissions rather than the minimal `permissions: read-all` scope, meaning a compromised action in the workflow dependency chain has write access to the repository ([F-032](#f-032)).

**Relevant findings**

- [F-032](#f-032) — GitHub Actions workflow lacks `permissions: read-all`; excessive GITHUB_TOKEN scope on every CI run.

<a id="sensitive-file-exposure"></a>
#### 7.11.4 Sensitive file exposure

**Status:** 🔴 Unsafe — `/ftp`, `/support/logs`, and `/encryptionkeys` serve sensitive files to unauthenticated HTTP requests.

`server.ts` mounts three static-file serving paths without authentication middleware: `/ftp` (serving `ftp/` directory contents), `/support/logs` (serving the access log directory), and `/encryptionkeys` (serving the `encryptionkeys/` directory). All three are accessible by anonymous HTTP clients.

**Security assessment**

- `/ftp` at `server.ts` serves the `ftp/` directory, which contains backup archives, user data exports, and other confidential files.
- `/support/logs` at `server.ts` serves the Express access log files, which contain IP addresses, request paths, and JWT tokens logged from `Authorization` headers.
- `/encryptionkeys` at `server.ts` serves `jwt.pub` and `premium.key` — the public counterpart of the committed RSA signing key plus a second key used for premium-feature validation.

**Relevant findings**

- [F-006](#f-006) — `/ftp` directory listing exposes confidential backup and data files to unauthenticated access.
- [F-020](#f-020) — `/support/logs` exposes access logs containing IP addresses and request metadata.
- [F-021](#f-021) — `/encryptionkeys` exposes `jwt.pub` and `premium.key` to unauthenticated requests.

<a id="automated-sca-scanning"></a>
#### 7.11.5 Automated SCA scanning

**Status:** 🟢 Adequate — `package-lock.json` is committed and Dependabot is configured; the tooling for automated SCA is in place.

`package-lock.json` records exact resolved versions for the full transitive dependency tree. Dependabot is configured in `.dependabot/config.yml` to monitor `npm` dependencies and raise update PRs.

**Security assessment**

The tooling infrastructure for SCA is present: a committed lockfile prevents non-deterministic installs, and Dependabot monitors the dependency graph. The `ignore` rules in the Dependabot config undermine the value of this tooling for the affected packages (see [F-034](#f-034)), but the baseline tooling is in place and functional for packages not in the ignore list.

**Relevant findings**

- [F-034](#f-034) — the Dependabot `ignore` rules suppress security updates for specific packages, reducing the effective value of the otherwise-adequate tooling.

<a id="automated-dependency-updates"></a>
#### 7.11.6 Automated dependency updates

**Status:** 🔴 Missing — Dependabot PRs are not auto-merged, and the `ignore` rules prevent update PRs from being raised for the highest-risk packages.

Dependabot can raise PRs automatically when vulnerabilities are detected, but the `.dependabot/config.yml` `auto-merged: false` setting means every PR requires manual review and merge. For the packages in the ignore list, no PR is raised at all.

**Security assessment**

The net effect is that security updates for pinned-vulnerable packages do not enter the merge queue. `express-jwt` at the version in `package.json` has a known algorithm-confusion exploit ([F-003](#f-003)). The Dependabot configuration explicitly prevents the automated update mechanism from surfacing the fix. Removing the `ignore` rules and enabling auto-merge for patch-range security updates (with the existing test suite as a gate) would restore the automated-update benefit.

**Relevant findings**

- [F-034](#f-034) — Dependabot ignore rules suppress the security-update PRs for packages with known exploitable versions.

<a id="lockfile-hygiene"></a>
#### 7.11.7 Lockfile hygiene

**Status:** 🔴 Missing — the CI pipeline does not run `npm ci` (which would enforce the lockfile); `npm install` is used, allowing lockfile drift.

`package-lock.json` is committed to the repository. The CI workflow uses `npm install` rather than `npm ci` in its dependency-install step. `npm install` will update `package-lock.json` in place if the installed versions differ from the locked ones; `npm ci` fails the build if the lockfile and `package.json` are out of sync.

**Security assessment**

Using `npm install` in CI means the lockfile does not gate the build. A dependency that drifts between `package.json` and `package-lock.json` — whether through a transitive range update or a registry substitution attack — installs without a CI failure. Replacing the install step with `npm ci --ignore-scripts` provides both lockfile enforcement and defence against lifecycle-script injection from malicious packages.

**Relevant findings**

- [F-040](#f-040) — no audit trail for B2B orders; the same operational gap that allows undiscovered supply-chain drift to persist without detection.

### 7.12 Real-time and Not Applicable Controls

**Verdict:** 🟡 Partial

**Controls covered:** [WebSocket and Socket.IO Security](#websocket-and-socketio-security), [Rate limiting (general)](#rate-limiting-general).

**Implemented controls:** `Socket.IO` v3 present for real-time challenge notifications; `express-rate-limit` library available in the dependency tree.

**Assessment:** `Socket.IO` is detected in `package.json` and used in `lib/startup/registerWebsocketEvents.ts` for server-to-client push notifications. No server-side rate limiting or message-size constraint is configured on the Socket.IO namespace. General rate limiting via `express-rate-limit` is available but applied only to specific non-login routes; the login endpoint ([F-030](#f-030)) and the Socket.IO connection handshake lack limits.

<a id="websocket-and-socketio-security"></a>
#### 7.12.1 WebSocket and Socket.IO Security

**Status:** 🟡 Partial — `Socket.IO` v3 is present for challenge notifications; no message-validation or rate-limiting is applied to the namespace.

`lib/startup/registerWebsocketEvents.ts` initialises a `Socket.IO` server attached to the Express HTTP server and registers event handlers for server-to-client push notifications. The `Socket.IO` connection handshake does not require a valid JWT; the namespace is open to unauthenticated clients.

The `Socket.IO` notification path is:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant SPA as Angular SPA
    participant WS as Socket.IO Server
    participant API as Express API

    User->>SPA: Load application
    SPA->>WS: Connect (no auth required)
    WS-->>SPA: Connection established
    API->>WS: Emit challenge-solved notification
    WS-->>SPA: Push notification to all connected clients

    alt Current state
        User->>WS: Send arbitrary message to namespace
        WS-->>SPA: Broadcast to all (no validation)
    else After mitigation
        User->>WS: Connect with valid JWT
        WS-->>User: 401 if no valid token present
    end
```

**Security assessment**

The `Socket.IO` namespace accepts connections from unauthenticated clients. Event handlers in `registerWebsocketEvents.ts` do not validate message structure or sender identity. No per-connection rate limit is applied to the handshake or to incoming messages. The namespace is used for read-only push notifications in the current implementation, which limits the direct exploit impact, but an unauthenticated persistent connection channel is a latent escalation surface if new event handlers are added without authentication review.

**Relevant findings**

- No dedicated `Socket.IO` finding was derived during this assessment. The channel is present and its gap is documented here as an architectural observation.

<a id="rate-limiting-general"></a>
#### 7.12.2 Rate limiting (general)

**Status:** 🟡 Partial — `express-rate-limit` is available and applied to some routes; the login endpoint and the B2B API lack limits.

`express-rate-limit` is declared as a dependency and applied to a subset of Express routes. The login route at `/rest/user/login` and the B2B endpoint at `/b2b/v2` are not covered. The package version in use is current.

**Security assessment**

The absence of rate limiting on the login route is assessed as a Critical gap in [§7.2](#72-identity-and-authentication-controls) ([F-030](#f-030)). The B2B endpoint's lack of rate limiting compounds the DoS risk from the infinite-loop finding ([F-029](#f-029)): a single authenticated user can submit an order that occupies the event loop indefinitely, and they can repeat this without rate-limit interference. Extending the existing `express-rate-limit` configuration to cover both routes would close both gaps.

**Relevant findings**

- [F-030](#f-030) — no rate limiting on the login endpoint allows unbounded brute-force.
- [F-029](#f-029) — no rate limiting on B2B endpoint amplifies the DoS impact of the infinite-loop finding.

### 7.13 Defense-in-Depth Summary

**Verdict:** 🔴 Unsafe

The strongest individual positive controls in this codebase are the RS256 algorithm choice for JWT signing (correctly avoiding the symmetric-key exposure of HS256), Helmet's baseline header set (noSniff, frameguard, `X-XSS-Protection`), multer's file-size limit on upload routes, and the committed `package-lock.json` with Dependabot monitoring. The CI test suite provides a functional regression gate. These controls are narrow in scope and isolated: none of them compensates for the category-level failures surrounding them.

Restoring layered defense requires closing the structural gaps in a specific order. Parameterised queries on the login and search routes eliminate the primary authentication bypass and exfiltration path. Runtime injection of the RSA private key and HMAC secret (via environment variables or a secrets manager) removes the public repository's status as an effectively public credential store. Replacing the eval-based B2B order processor with structured JSON schema validation eliminates the only RCE path in the model. Adding `Content-Security-Policy: default-src 'self'` and restricting the CORS origin allowlist to the application's own domain converts the browser-side XSS and CSRF surface from exploitable to aspirational. These four repairs address eleven of the eleven Critical findings without touching the High-severity surface.

<!-- enriched:thorough -->
