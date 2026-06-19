## 7. Security Architecture

The following sections evaluate the security control architecture of OWASP Juice Shop across 13 control domains. Each domain is rated against code evidence from the repository. Because Juice Shop is a deliberately vulnerable training application, most domains are rated Unsafe or Missing by design.

### 7.1 Security Control Overview

<!-- §7.1 MECHANICAL-FROZEN: the table below is emitted by the pregenerator from threat-model.yaml. Do not re-author. -->
| Control category | Verdict | Main reason |
|-----------------|---------|-------------|
| [Identity and Authentication](#72-identity-and-authentication-controls) | 🔴 Unsafe | SQL injection on login, hardcoded RSA private key, and unsalted MD5 password hashing collapse the authentication boundary |
| [Session and Token Controls](#73-session-and-token-controls) | 🔴 Unsafe | JWTs stored in `localStorage` (XSS-accessible), no server-side logout, and forged tokens valid for the full 6-hour window |
| [Authorization Controls](#74-authorization-controls) | 🟠 Weak | JWT role claim present; ownership check absent on 18 object-level endpoints |
| [Query Construction and Data Access](#75-query-construction-and-data-access-controls) | 🔴 Unsafe | Raw SQL interpolation in login and search; NoSQL selector injection in review updates |
| [Input Boundary Validation](#76-input-boundary-validation-controls) | 🟠 Weak | No global validation middleware; `eval()` on user input; outdated `sanitize-html` |
| [Output Encoding and Rendering](#77-output-encoding-and-rendering-controls) | 🔴 Unsafe | Helmet XSS filter disabled; user-controlled CSP header injection enables stored XSS |
| [Browser and Cross-Origin Controls](#78-browser-and-cross-origin-controls) | 🔴 Unsafe | Wildcard CORS and no Content-Security-Policy header |
| [Cryptography Secrets and Data Protection](#79-cryptography-secrets-and-data-protection-controls) | 🔴 Unsafe | Four hardcoded secrets in a public repository; unsalted MD5 for password storage |
| [File Parser and Outbound Request Controls](#710-file-parser-and-outbound-request-controls) | 🔴 Unsafe | XXE with `noent:true` enabled; SSRF with no URL allowlist |
| [Operations Runtime and Supply Chain](#711-operations-runtime-and-supply-chain-controls) | 🟠 Weak | No lockfile; critically outdated JWT libraries; unpinned CI action refs |
| [Real-time and Not Applicable Controls](#712-real-time-and-not-applicable-controls) | 🟡 Partial | `Socket.IO` present; per-message JWT re-validation gap |
<!-- §7.1 MECHANICAL-FROZEN END -->

### 7.2 Identity and Authentication Controls

**Verdict:** 🔴 Unsafe

**Controls covered:** [7.2.1 Password-Based Authentication](#721-password-based-authentication), [7.2.2 Multi-Factor Authentication (TOTP)](#722-multi-factor-authentication-totp), [7.2.3 Social Login Adapter (OAuth / OIDC)](#723-social-login-adapter-oauth-oidc), [7.2.4 Password Reset](#724-password-reset), [7.2.5 Anonymous Access Controls](#725-anonymous-access-controls)

**Implemented controls:** Password login via `routes/login.ts`, optional TOTP via `routes/2fa.ts`, Google OAuth adapter in `oauth.component.ts`, password reset via `routes/resetPassword.ts`

**Assessment:** Authentication is structurally present at every layer but cryptographically or logically broken at each. The login path uses raw SQL string interpolation, making the password check bypassable without knowing a valid password. Password storage uses unsalted MD5. JWT signing relies on a hardcoded 1024-bit RSA private key committed to a public repository. The JWT verifier at `lib/insecurity.ts:54` does not pin the algorithm, enabling an `alg:none` bypass with `express-jwt@0.1.3`. Each successful authentication flow terminates in the server issuing a session token; the signing, validation, storage, and lifecycle of that token are described in [§7.3 Session and Token Controls](#73-session-and-token-controls).

<a id="721-password-based-authentication"></a>

#### 7.2.1 Password-Based Authentication

**Status:** 🔴 Unsafe — SQL injection bypasses the credential check entirely, and unsalted MD5 makes any exfiltrated hash immediately recoverable.

`routes/login.ts` handles credential verification. The route receives `req.body.email` and `req.body.password`, hashes the password using `security.hash()` from `lib/insecurity.ts`, and issues an authenticated session. Registration at `server.ts:407` writes the hashed password to the `Users` table. Password change at `routes/changePassword.ts` re-hashes the new value with the same primitive. The full lifecycle — login, registration, change — feeds the same `security.hash()` function at `lib/insecurity.ts:43`.

The diagram shows the intended password login path and where it breaks down:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant SPA as Angular SPA
    participant API as "routes/login.ts"
    participant DB as "SQLite Users table"
    participant JWT as "lib/insecurity.ts"

    User->>SPA: Enter email + password
    SPA->>API: POST /rest/user/login
    API->>DB: SELECT * FROM Users WHERE email='...' AND password='...'
    DB-->>API: First matching user row (or empty)
    API->>JWT: issueAuthToken(user)
    JWT-->>API: Signed RS256 JWT
    API-->>SPA: { token, bid, umail }

    alt Current state
        note over API,DB: email is raw string interpolation — SQL injection bypasses password check
    else After mitigation
        note over API,DB: Parameterized query validates both email AND password hash
    end
```

**Security assessment**

Two independent weaknesses sit on the password login path:

- `routes/login.ts:34` interpolates `req.body.email` directly into a raw SQL string: `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(...)}'`. The payload `' OR 1=1--` short-circuits the WHERE clause and returns the seeded admin account.
- `lib/insecurity.ts:43` implements `security.hash()` as `crypto.createHash('md5').update(data).digest('hex')` — a single-round, unsalted MD5. Any dump obtained through injection immediately yields passwords recoverable by rainbow tables.

**Relevant findings**

- [T-004](#t-004) — SQL injection at `routes/login.ts:34` allows authentication bypass without a valid credential.
- [T-022](#t-022) — Unsalted MD5 password hashing makes every stored credential trivially reversible.
- [T-036](#t-036) — Duplicate MD5 hashing finding from `data-layer` component confirming the same primitive at `lib/insecurity.ts:43`.
- [T-043](#t-043) — No rate limiting on the login endpoint permits unbounded brute-force attempts.
- [T-045](#t-045) — Overlapping login brute-force finding from the `express-backend` component.

<a id="722-multi-factor-authentication-totp"></a>

#### 7.2.2 Multi-Factor Authentication (TOTP)

**Status:** 🟡 Partial — TOTP enrollment and verification are implemented but the factor is optional and bypassed by the JWT forgery path.

TOTP is available as an opt-in second factor via `routes/2fa.ts`. A user who has enabled 2FA must present a valid TOTP code during login via a two-step flow: the first step verifies the password and issues a partial session; the second step (`POST /rest/2fa/verify`) consumes the TOTP token and issues a full JWT. The `otplib` library handles HMAC-TOTP generation and verification.

**Security assessment**

- **Enrollment** (🟢 Adequate): `routes/2fa.ts` correctly generates a per-user TOTP secret with `otplib` and stores it encrypted.
- **Verification** (🟡 Partial): Verification logic at `routes/2fa.ts:158` compares the submitted TOTP token against the stored secret, but the check uses `security.hash()` (MD5) to derive a comparison value from the stored MD5 password hash, meaning an attacker who can compute an MD5 preimage of the target password disables 2FA.
- The JWT forgery path ([T-005](#t-005)) bypasses TOTP entirely — an attacker who mints a valid admin token with the committed private key never interacts with the 2FA flow.

**Relevant findings**

- [T-050](#t-050) — TOTP disable bypass via MD5 password preimage at `routes/2fa.ts:158`.

<a id="723-social-login-adapter-oauth-oidc"></a>

#### 7.2.3 Social Login Adapter (OAuth / OIDC)

**Status:** 🟠 Weak — the OAuth flow is a frontend-only adapter that terminates in the same broken local login path.

`oauth.component.ts` implements a Google OAuth2 frontend adapter, not a server-side authorization-code flow. The component reads an access token from the redirect URL, calls the Google userinfo endpoint through `UserService.oauthLogin()`, derives a deterministic local password from the returned email address, creates a local `Users` row if absent, and then calls the standard `POST /rest/user/login` endpoint.

The diagram shows how the OAuth adapter routes through local login:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant SPA as "oauth.component.ts"
    participant Google as "Google UserInfo API"
    participant API as "Local User + Login API"
    participant JWT as "JWT Issuer"

    User->>SPA: Return from OAuth redirect with access token
    SPA->>Google: Fetch user profile (email)
    Google-->>SPA: Email address
    SPA->>API: Create local user if absent
    SPA->>API: POST /rest/user/login (derived password)
    API->>JWT: Issue local session JWT
    API-->>SPA: JWT + basket id
```

**Security assessment**

This is not a full server-side OAuth/OIDC authorization-code control. Google identity is used only as a frontend identity hint; the resulting session is a local password-login session with all its weaknesses intact. Because the derived password is computed deterministically from the email address ([T-003](#t-003)), any party who knows the algorithm and the target email can generate a valid credential without Google interaction.

**Relevant findings**

- [T-003](#t-003) — OAuth-derived password from email allows credential bypass without completing an OAuth flow.
- [T-015](#t-015) — OAuth implicit flow without state or PKCE exposes the access token to token substitution.
- [T-027](#t-027) — OAuth access token exposed in the URL fragment via implicit flow.

<a id="724-password-reset"></a>

#### 7.2.4 Password Reset

**Status:** 🔴 Unsafe — security-question reset has no rate limit and the X-Forwarded-For header can be spoofed to bypass IP-based throttle.

`routes/resetPassword.ts` implements password reset as a single-step security-question challenge: the caller supplies `email`, the security question answer, and a new `password`. The route compares the supplied answer against the stored value and updates the `Users.password` column directly with the MD5 hash of the new password.

**Security assessment**

- No emailed token or out-of-band confirmation is required. A correct reset path would issue a single-use token via a verified channel.
- The rate-limit key at `server.ts:346` uses `req.headers['x-forwarded-for']` rather than the server-validated remote IP. Any client can set this header to rotate the apparent source IP and avoid per-IP throttling.

**Relevant findings**

- [T-016](#t-016) — Rate-limit bypass via attacker-controlled `X-Forwarded-For` at `server.ts:346`.

<a id="725-anonymous-access-controls"></a>

#### 7.2.5 Anonymous Access Controls

**Status:** 🔴 Unsafe — management surfaces, data export, and file upload endpoints are reachable without credentials.

Juice Shop registers route handlers in `server.ts`. Authentication middleware (`isAuthorized()` from `lib/insecurity.ts`) is applied selectively. Several categories of endpoint are intentionally or accidentally missing the middleware: the multipart file upload at `server.ts:309-311`, all continue-code endpoints, the data-export endpoint `POST /rest/user/data-export`, wallet balance mutation `PUT /rest/wallet/balance`, and management surfaces `/rest/admin/application-configuration` and `/rest/admin/application-version`.

**Security assessment**

- `POST /file-upload`, `POST /profile/image/file`, and `POST /profile/image/url` at `server.ts:309-311` are registered before `isAuthorized()` is applied, leaving them open to unauthenticated callers.
- `/rest/admin/application-configuration` and `/rest/admin/application-version` at `server.ts:604-605` expose detailed runtime configuration and deployed version to unauthenticated requests.
- `POST /rest/user/data-export` at `server.ts:618` allows data export without credential verification.

**Relevant findings**

- [T-018](#t-018) — Missing authentication on `POST /file-upload` at `server.ts:309`.
- [T-051](#t-051) — Sensitive routes registered without authentication middleware across `server.ts`.
- [T-052](#t-052) — Unauthenticated admin endpoints at `server.ts:604`.

### 7.3 Session and Token Controls

**Verdict:** 🔴 Unsafe

**Controls covered:** [7.3.1 Session Token Signing (JWT Based)](#731-session-token-signing-jwt-based), [7.3.2 Session Token Validation (JWT Based)](#732-session-token-validation-jwt-based), [7.3.3 Session Token Storage (Browser localStorage)](#733-session-token-storage-browser-localstorage), [7.3.4 Session Token Revocation](#734-session-token-revocation), [7.3.5 Session Token Expiry](#735-session-token-expiry)

**Implemented controls:** RS256 JWT signing via `lib/insecurity.ts`; `express-jwt@0.1.3` for token validation; `authenticatedUsers` in-memory map; 6-hour token expiry

**Assessment:** This application uses a single locally-signed token format (commonly called JWT) for every authenticated session, regardless of the login flow in §7.2 that established it. The sub-sections below trace one token through its lifecycle: signing on issuance, validation on every protected request, storage in the browser, manual revocation, and time-based expiry. Every stage of the lifecycle is compromised: the signing key is public, the verifier accepts algorithm substitution, tokens are stored in XSS-accessible `localStorage`, server-side revocation does not exist, and the 6-hour expiry is the only constraint on a stolen or forged token.

<a id="731-session-token-signing-jwt-based"></a>

#### 7.3.1 Session Token Signing (JWT Based)

**Status:** 🔴 Unsafe — the RSA private key is committed to the public repository; any reader can mint valid admin tokens offline.

⚠ **Anti-pattern:** Secrets hardcoded in source

`lib/insecurity.ts` exports `issueAuthToken()`, which signs a `{ id, email, role }` payload with a 1024-bit RSA private key using `jsonwebtoken@0.4.0`. The private key is declared as a multi-line string constant at `lib/insecurity.ts:23`. Both `routes/login.ts` and `routes/2fa.ts` call this helper, so all session tokens share the same key material.

The diagram shows the signing path and the broken key boundary:

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant Repo as "Public GitHub Repo"
    participant CLI as "Local jwt.sign()"
    participant API as "Express API"

    alt Current state
        Attacker->>Repo: git clone then read lib/insecurity.ts:23
        Repo-->>Attacker: RSA private key PEM
        Attacker->>CLI: jwt.sign({role:"admin"}, privateKey, {algorithm:"RS256"})
        CLI-->>Attacker: Valid admin JWT
        Attacker->>API: Authorization: Bearer <forged token>
        API-->>Attacker: 200 OK — admin response
    else After mitigation
        note over API: Key loaded from external secret store, not source — old tokens invalid after rotation
    end
```

**Security assessment**

The private key at `lib/insecurity.ts:23` is a 1024-bit RSA key below NIST SP 800-131A's 2048-bit minimum. Because it is committed to a public GitHub repository (referenced at `https://github.com/juice-shop/juice-shop`), it is permanently compromised. Rotating the key requires a new secret store reference and token invalidation — a `git revert` of the commit does not help because the key is in git history.

The hardcoded key assignment that breaks the signing boundary:

```ts
export const privateKey =
  '-----BEGIN RSA PRIVATE KEY-----\nMIICXA...'  // 1704 chars
```

**Relevant findings**

- [T-005](#t-005) — Hardcoded RSA private key at `lib/insecurity.ts:23` enables universal JWT forgery.
- [T-028](#t-028) — Hardcoded Ethereum wallet mnemonic at `routes/checkKeys.ts:10` exposes a second committed secret.

<a id="732-session-token-validation-jwt-based"></a>

#### 7.3.2 Session Token Validation (JWT Based)

**Status:** 🔴 Unsafe — `express-jwt@0.1.3` without an `algorithms` restriction accepts `alg:none`, allowing signature-free tokens.

`lib/insecurity.ts:54` configures `express-jwt` as the protected-route middleware. The configuration passes only the public key; no `algorithms` property is set. `jws.verify()` at `lib/insecurity.ts:57-58` additionally accepts the decoded header algorithm value without pinning to `RS256`.

The diagram shows the validation path under attack:

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant API as "express-jwt middleware"
    participant Lib as "lib/insecurity.ts:54"

    alt Current state
        Attacker->>API: Authorization: Bearer <header.payload.> (alg=none, empty sig)
        API->>Lib: jws.verify(token, key, {algorithms: undefined})
        Lib-->>API: Valid — no algorithm check
        API-->>Attacker: 200 OK — route allowed
    else After mitigation
        Attacker->>API: Same alg:none token
        API->>Lib: Verify with algorithms:["RS256"] pinned
        Lib-->>API: Rejected — algorithm not allowed
        API-->>Attacker: 401 Unauthorized
    end
```

**Security assessment**

`express-jwt@0.1.3` (current: `8.4.1`) predates the mandatory `algorithms` field. An attacker crafts a token with `"alg": "none"` in the header, an empty signature, and any `role` claim. The verifier at `lib/insecurity.ts:54-58` accepts it. This finding is independent of the committed private key — even after key rotation, the `alg:none` bypass allows forging tokens without key material.

The vulnerable middleware configuration:

```ts
export const isAuthorized = () => expressJwt({
  secret: publicKey   // no algorithms: ['RS256'] restriction
})
```

**Relevant findings**

- [T-006](#t-006) — `alg:none` bypass via `express-jwt@0.1.3` at `lib/insecurity.ts:54`.
- [T-049](#t-049) — JWT role claims are not validated against the database at request time, allowing stale privilege escalation.

<a id="733-session-token-storage-browser-localstorage"></a>

#### 7.3.3 Session Token Storage (Browser localStorage)

**Status:** 🔴 Unsafe — tokens in `localStorage` are readable by any JavaScript in the page's origin, including injected XSS payloads.

⚠ **Anti-pattern:** JWT in localStorage

`login.component.ts:101` stores the JWT returned by the login API in `localStorage`: `this.localStorage.setItem('token', result.authentication.token)`. `request.interceptor.ts:13` reads it back and attaches it as a `Bearer` token to every subsequent API request.

**Security assessment**

`localStorage` is accessible to any script running in the same origin, including attacker-injected payloads from the XSS findings in §7.7. The theft sequence is: (1) attacker triggers stored XSS via a malicious product description; (2) victim browser executes `localStorage.getItem('token')`; (3) token is exfiltrated to an attacker-controlled endpoint; (4) attacker replays the token for the full 6-hour lifetime with no server-side detection.

An `HttpOnly Secure SameSite=Strict` cookie would prevent JavaScript access, eliminating the XSS-to-token-theft chain.

**Relevant findings**

- [T-001](#t-001) — JWT stored in `localStorage` at `login.component.ts:101`.
- [T-002](#t-002) — Duplicate storage finding at `request.interceptor.ts:13` confirming the pattern across components.

<a id="734-session-token-revocation"></a>

#### 7.3.4 Session Token Revocation

**Status:** 🔴 Missing — no server-side revocation mechanism exists; `localStorage.removeItem('token')` on the client has no effect on the server.

`lib/insecurity.ts:72` maintains an `authenticatedUsers` in-memory map that associates tokens with user objects. This map is populated on login but is never cleared on logout — logout is client-side only (deleting the token from `localStorage`). There is no `/rest/user/logout` endpoint that invalidates the server-side map entry.

**Security assessment**

An attacker who obtains a JWT via XSS-to-localStorage theft retains access for the full 6-hour expiry window even if the victim logs out. The in-memory map also does not survive server restarts, meaning tokens minted before a restart become orphaned — a secondary issue, not a security control.

**Relevant findings**

- [T-001](#t-001) — JWT theft enabled by `localStorage` storage persists through user-initiated logout.
- [T-002](#t-002) — Same token storage pattern in the HTTP interceptor extends the scope.

<a id="735-session-token-expiry"></a>

#### 7.3.5 Session Token Expiry

**Status:** 🟡 Partial — a 6-hour expiry is set in the JWT payload, but forged tokens can carry any expiry the attacker chooses.

`lib/insecurity.ts:issueAuthToken()` sets `{ expiresIn: '6h' }` via `jsonwebtoken`. The `express-jwt` middleware at `lib/insecurity.ts:54` validates the `exp` claim when it reads a genuine token.

**Security assessment**

The 6-hour expiry is the only time-based constraint on session lifetime. Because the private key is public and the algorithm check is absent, an attacker can mint a token with `exp: 9999999999` (year 2286) that the verifier accepts indefinitely. Expiry is a partial control only when the signing boundary is intact.

**Relevant findings**

- [T-005](#t-005) — Forged tokens carry any expiry the attacker sets; the 6-hour constraint does not apply.

### 7.4 Authorization Controls

**Verdict:** 🟠 Weak

**Controls covered:** [7.4.1 Role-Based Access Control](#741-role-based-access-control), [7.4.2 Object-Level Authorization (IDOR)](#742-object-level-authorization-idor)

**Implemented controls:** `isAuthorized()` middleware from `lib/insecurity.ts` enforces JWT presence on protected routes; `role` claim (`admin` / `customer`) encoded in JWT payload

**Assessment:** Role-level access control at the route boundary is structurally present but ineffective due to the broken signing boundary in §7.3. Object-level authorization is absent: any authenticated user can substitute an arbitrary object ID in address, payment, order, memory, and wallet endpoints and receive or modify data belonging to another user.

<a id="741-role-based-access-control"></a>

#### 7.4.1 Role-Based Access Control

**Status:** 🟠 Weak — the `role` claim in the JWT is checked but can be forged via the committed private key or the `alg:none` bypass.

`isAuthorized()` at `lib/insecurity.ts:54` decodes the JWT and exposes the `role` claim to downstream handlers. Admin-only endpoints check `req.user.role === 'admin'` before proceeding. The role is not re-validated against the database at request time.

**Security assessment**

The role check is structurally correct but bypassed by both [T-005](#t-005) (committed private key) and [T-006](#t-006) (`alg:none`). Either path allows minting a token with `role: "admin"` without user interaction. Additionally, `POST /api/Users` does not exclude the `role` field from mass-assignment ([T-009](#t-009) and [T-013](#t-013)), allowing any user to self-assign admin role at registration.

**Relevant findings**

- [T-009](#t-009) — Mass assignment: `role` field writable via `POST /api/Users` at `server.ts:483`.
- [T-013](#t-013) — Mass assignment admin role via user registration at `server.ts:499`.
- [T-048](#t-048) — Client-side Angular route guards at `app.guard.ts:17` are bypassable without server-side authorization.
- [T-049](#t-049) — JWT role claims not validated against the database at request time.

<a id="742-object-level-authorization-idor"></a>

#### 7.4.2 Object-Level Authorization (IDOR)

**Status:** 🔴 Missing — endpoints accept any object ID from the request path or body without verifying the authenticated user owns that object.

`routes/address.ts`, `routes/payment.ts`, `routes/order.ts`, `routes/wallet.ts`, `routes/memory.ts`, `routes/basketItems.ts`, and related handlers perform database lookups using the caller-supplied ID. None of them include an ownership predicate (`WHERE userId = req.user.id`).

**Security assessment**

An authenticated user at `routes/address.ts:11` can substitute any `addressId` in the path and retrieve another user's delivery address. The same pattern applies to payment card references, order history, wallet balance, and deluxe membership status. There are 18 such endpoints identified across the application.

**Relevant findings**

- [T-007](#t-007) — Insecure Direct Object Reference across 18 endpoints covering address, payment, order, wallet, and memory resources.

### 7.5 Query Construction and Data Access Controls

**Verdict:** 🔴 Unsafe

**Controls covered:** [7.5.1 SQL Query Construction (Sequelize + Raw Queries)](#751-sql-query-construction-sequelize-raw-queries), [7.5.2 NoSQL Query Construction (MarsDB)](#752-nosql-query-construction-marsdb)

**Implemented controls:** Sequelize 6.37.3 ORM available and used for most entity operations; MarsDB for in-memory chatbot/memory storage

**Assessment:** Two confirmed SQL injection points exist on the application's most-trafficked endpoints — authentication and the primary product search. Both bypass the Sequelize ORM in favour of raw query strings with string interpolation. The NoSQL layer in MarsDB additionally accepts a user-controlled selector structure that allows operator injection.

<a id="751-sql-query-construction-sequelize-raw-queries"></a>

#### 7.5.1 SQL Query Construction (Sequelize + Raw Queries)

**Status:** 🔴 Unsafe — login and search routes bypass the ORM and interpolate user input directly into SQL strings.

Sequelize models in `models/` generate parameterized queries for most CRUD operations. Two routes deviate: `routes/login.ts:34` builds the authentication query with `models.sequelize.query()` and a template literal; `routes/search.ts:23` does the same for the product search query. These are the two highest-traffic entry points in the application.

The product search route illustrates the raw-string construction that bypasses the ORM:

```ts
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'
    OR description LIKE '%${criteria}%') AND deletedAt IS NULL)
   ORDER BY name`)
```

**Security assessment**

`routes/login.ts:34` interpolates `req.body.email` without sanitization. The payload `' OR '1'='1` short-circuits the WHERE clause and returns the first `Users` row, which is the seeded admin account. `routes/search.ts:23` interpolates `req.query.q` directly; a UNION-based payload can exfiltrate the full Users table including MD5 hashes.

**Relevant findings**

- [T-004](#t-004) — SQL injection in the login query allows authentication bypass without credentials.
- [T-008](#t-008) — UNION-based SQL injection in the product search enables full database exfiltration.

<a id="752-nosql-query-construction-marsdb"></a>

#### 7.5.2 NoSQL Query Construction (MarsDB)

**Status:** 🔴 Unsafe — `routes/updateProductReviews.ts:18` passes a user-controlled MarsDB selector, enabling mass update via `multi:true`.

MarsDB backs the in-memory product review store. `routes/updateProductReviews.ts:18` calls `db.update(req.body.id, ...)` where `req.body.id` is the product review selector supplied by the caller. MarsDB supports MongoDB-style selectors including operators like `$gt` and `$regex`.

**Security assessment**

A caller who submits `{"id": {"$gt": ""}}` as the selector matches all reviews in the database. Combined with `multi: true` in the update options, this overwrites every product review in one request. The selector field is not validated against a whitelist of scalar ID values before it is passed to MarsDB.

**Relevant findings**

- [T-025](#t-025) — NoSQL injection via user-controlled MarsDB selector at `routes/updateProductReviews.ts:18`.

### 7.6 Input Boundary Validation Controls

**Verdict:** 🟠 Weak

**Controls covered:** [7.6.2 Input Validation and Sanitization](#762-input-validation-and-sanitization), [7.6.3 Server-Side Code Evaluation (notevil sandbox)](#763-server-side-code-evaluation-notevil-sandbox)

**Implemented controls:** `sanitize-html@1.4.2` used in some response paths; `sanitize-filename@1.6.3` for uploaded file names; `sanitizeSecure()` recursive function in `lib/insecurity.ts`

**Assessment:** No global input validation middleware is registered. Critical paths — login email, product search query, profile username — receive no sanitization. The outdated `sanitize-html@1.4.2` has documented bypass techniques. The profile username field at `routes/userProfile.ts:62` is evaluated via `eval()` rather than any validator, creating a direct code-execution path.

<a id="762-input-validation-and-sanitization"></a>

#### 7.6.2 Input Validation and Sanitization

**Status:** 🟠 Weak — sanitization is applied inconsistently and the available sanitizer is critically outdated.

`sanitize-html@1.4.2` is imported in `lib/insecurity.ts` and used in some API response paths. `sanitize-filename@1.6.3` normalizes uploaded file names before they are written to disk. The recursive `sanitizeSecure()` function applies `sanitize-html` to nested objects. However, `routes/login.ts`, `routes/search.ts`, and the B2B order body receive no input validation before they reach their respective sinks.

**Security assessment**

- `sanitize-html@1.4.2` is approximately 8 major versions behind the current `2.x` line. Known bypass techniques affect the 1.x series.
- No schema validation library (joi, zod, ajv) is registered as global middleware. Each route is responsible for its own validation, and several omit it entirely.
- The most severe omission is `routes/userProfile.ts:62` (addressed in §7.6.3), where the absence of validation leads directly to code execution rather than injection.

**Relevant findings**

- [T-012](#t-012) — Server-side template injection via `eval()` at `routes/userProfile.ts:62`.

<a id="763-server-side-code-evaluation-notevil-sandbox"></a>

#### 7.6.3 Server-Side Code Evaluation (notevil sandbox)

**Status:** 🔴 Unsafe — two independent code-evaluation sinks exist; the notevil sandbox is escapable and `eval()` in the profile route has no sandbox.

`routes/userProfile.ts:62` calls `eval(req.body.username)` directly on the user-supplied profile name. `routes/b2bOrder.ts:23` passes the `orderLinesData` field to `vm.runInContext(safeEval(orderLinesData), ctx)`, where `safeEval` is the `notevil` package.

**Security assessment**

Two independent paths to server-side code execution:

- `routes/userProfile.ts:62`: `eval()` with no sandbox. Any JavaScript the attacker supplies in the `username` field executes with the full Node.js process privileges.
- `routes/b2bOrder.ts:23`: `notevil` is a known-escape-prone sandbox (CVE history). A crafted `orderLinesData` payload can escape the VM context and access the global `process` object.

The `eval()` call at `routes/userProfile.ts:62`:

```ts
const updatedUser = await UserModel.update(
  { username: eval(username) },   // username = req.body.username
  { where: { id: req.user?.id } }
)
```

**Relevant findings**

- [T-012](#t-012) — Server-side code execution via `eval()` at `routes/userProfile.ts:62`.
- [T-011](#t-011) — JavaScript sandbox escape via `notevil` at `routes/b2bOrder.ts:23`.

### 7.7 Output Encoding and Rendering Controls

**Verdict:** 🔴 Unsafe

**Controls covered:** [7.7.1 XSS Prevention (Angular Template + DomSanitizer)](#771-xss-prevention-angular-template-domsanitizer), [7.7.2 Output Encoding and CSP Header Injection](#772-output-encoding-and-csp-header-injection)

**Implemented controls:** Angular template binding provides default context-aware escaping for interpolation expressions; `sanitize-html@1.4.2` used in some backend responses

**Assessment:** Angular's template engine escapes interpolation by default, providing baseline protection for data rendered through `{{ }}` bindings. This protection is deliberately bypassed in two components via `bypassSecurityTrustHtml()`. The Helmet XSS filter is disabled. A stored XSS path via a user-controlled CSP response header makes the application's own user-profile feature an XSS delivery mechanism.

<a id="771-xss-prevention-angular-template-domsanitizer"></a>

#### 7.7.1 XSS Prevention (Angular Template + DomSanitizer)

**Status:** 🔴 Unsafe — `DomSanitizer.bypassSecurityTrustHtml()` is called on attacker-controlled product description and search result content.

Angular's `DomSanitizer` sanitizes HTML before it is bound to `[innerHTML]`. `search-result.component.ts:132` calls `this.sanitizer.bypassSecurityTrustHtml(product.description)` before binding the product description. `search-result.component.ts:170` applies the same bypass to the unsanitized search query reflected in the results heading.

**Security assessment**

- `search-result.component.ts:132`: product descriptions from the database are marked trusted before HTML binding. A malicious product description (inserted via an admin-capable SQL injection or directly) renders as live HTML including `<script>` tags.
- `search-result.component.ts:170`: the search parameter from `req.query.q` flows through the API response into the results heading with `bypassSecurityTrustHtml`. This is a reflected DOM XSS vector affecting every unauthenticated visitor.

**Relevant findings**

- [T-020](#t-020) — Stored XSS in product descriptions via `bypassSecurityTrustHtml` at `search-result.component.ts:132`.
- [T-021](#t-021) — Reflected DOM XSS via unsanitized search query at `search-result.component.ts:170`.
- [T-053](#t-053) — DOM XSS via last-login IP from JWT payload at `last-login-ip.component.ts:39`.

<a id="772-output-encoding-and-csp-header-injection"></a>

#### 7.7.2 Output Encoding and CSP Header Injection

**Status:** 🔴 Unsafe — the Helmet XSS filter is disabled and a user-controlled value is interpolated into a CSP response header.

`server.ts:187` contains a commented-out `app.use(helmet.xssFilter())` call. `routes/userProfile.ts:88` constructs a per-response CSP header using the user's stored profile image URL: `` const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'` ``.

**Security assessment**

If an attacker sets their profile image URL to a value containing a semicolon followed by `script-src 'unsafe-inline'`, the injected string extends the CSP header and enables inline script execution in the victim's browser. This is a stored XSS vector via HTTP response header injection, distinct from the template-binding bypass in §7.7.1.

The header construction at `routes/userProfile.ts:88`:

```ts
res.set('Content-Security-Policy',
  `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`)
```

**Relevant findings**

- [T-020](#t-020) — CSP header injection path amplifies stored XSS impact.
- [T-026](#t-026) — Missing global CSP header leaves script execution unrestricted.

### 7.8 Browser and Cross-Origin Controls

**Verdict:** 🔴 Unsafe

**Controls covered:** [7.8.1 CORS Policy](#781-cors-policy), [7.8.2 Content Security Policy](#782-content-security-policy)

**Implemented controls:** `helmet.noSniff()` — `X-Content-Type-Options: nosniff`; `helmet.frameguard()` — `X-Frame-Options: SAMEORIGIN`; `cors` module present

**Assessment:** Two of the six Helmet sub-modules are enabled. CORS is configured with wildcard origin, permitting cross-origin requests from any website. No global CSP is set — the only CSP header in the application is the per-user, user-injectable one addressed in §7.7.2.

<a id="781-cors-policy"></a>

#### 7.8.1 CORS Policy

**Status:** 🔴 Unsafe — `app.use(cors())` with no `origin` restriction allows any web page on the internet to read cross-origin responses.

`server.ts:181-182` calls `app.options('*', cors())` and `app.use(cors())` with the default `cors()` configuration. The default passes all origins via `Access-Control-Allow-Origin: *`.

**Security assessment**

A wildcard CORS policy on a cookie-less API that uses `Authorization` header tokens does not allow cookie-based cross-site request forgery. However, it does allow any page to read the response body from API requests. If an XSS payload on a third-party site can cause an authenticated Juice Shop session to make a credentialed fetch (using the stored `localStorage` token), the attacker can read the response. The absence of `credentials: 'include'` for cookie-based flows is a partial mitigation that does not apply to the token-in-header pattern.

**Relevant findings**

- No dedicated finding in the threat model for wildcard CORS. This control gap amplifies the impact of findings [T-001](#t-001) and [T-020](#t-020).

<a id="782-content-security-policy"></a>

#### 7.8.2 Content Security Policy

**Status:** 🔴 Missing — `helmet.contentSecurityPolicy()` is not called; there is no global CSP protecting the Angular SPA's document origin.

`server.ts` applies `helmet.frameguard()` and `helmet.noSniff()` but does not call `helmet.contentSecurityPolicy()`. The only CSP present in the application is the per-user, user-injectable header in `routes/userProfile.ts:88`, which is the XSS delivery mechanism rather than a control.

**Security assessment**

Without a CSP, the Angular SPA's origin has no restriction on which scripts can execute, which URIs can be fetched, or where forms can submit. A stored XSS payload in a product description renders and executes inline with no browser-level containment. A baseline CSP (`script-src 'self'` with a nonce or hash) would prevent the `bypassSecurityTrustHtml` findings from resulting in arbitrary script execution.

**Relevant findings**

- [T-020](#t-020) — Stored XSS execution would be blocked by a strict `script-src` CSP directive.
- [T-021](#t-021) — Reflected DOM XSS execution likewise constrained by CSP.

### 7.9 Cryptography Secrets and Data Protection

**Verdict:** 🔴 Unsafe

**Controls covered:** [7.9.1 Secret Management](#791-secret-management), [7.9.2 Password Storage](#792-password-storage)

**Implemented controls:** None — all secrets are hardcoded constants in source files; password hashing exists but uses an insecure algorithm

**Assessment:** This is the most comprehensively broken control domain. Four distinct secrets are hardcoded in source files committed to a public repository. No environment variable injection, no secrets manager, no HSM, and no key rotation mechanism exists. Password hashing is present but uses unsalted MD5, which provides no practical protection against offline recovery.

<a id="791-secret-management"></a>

#### 7.9.1 Secret Management

**Status:** 🔴 Unsafe — four secrets are committed to the public GitHub repository; rotation is not possible without a code change and deployment.

`lib/insecurity.ts` exports four constants that constitute the application's secret material: the RSA private key at line 23, the HMAC signing secret at line 44, the cookie parser secret embedded in `server.ts:289`, and support-user credentials stored inline at `routes/login.ts:60-66`.

**Security assessment**

All four secrets are permanently exposed in git history regardless of any subsequent commit. The chain of impact:

- RSA private key → any caller can forge admin JWTs ([T-005](#t-005))
- HMAC secret → HMAC-signed request values can be forged
- Cookie secret → cookie signatures can be predicted
- Support credentials → direct account access for the support user

No secret store (AWS Secrets Manager, HashiCorp Vault, environment variable injection, or Kubernetes secret) is used anywhere in the codebase.

**Relevant findings**

- [T-005](#t-005) — Hardcoded RSA private key enables universal JWT forgery.
- [T-028](#t-028) — Hardcoded Ethereum wallet mnemonic at `routes/checkKeys.ts:10`.
- [T-030](#t-030) — Hardcoded deployment email in public workflow at `.github/workflows/ci.yml:342`.

<a id="792-password-storage"></a>

#### 7.9.2 Password Storage

**Status:** 🔴 Unsafe — passwords are hashed with unsalted MD5; a database dump directly yields recoverable plaintexts for most common passwords.

`lib/insecurity.ts:43` implements `security.hash()` as a single call to `crypto.createHash('md5').update(data).digest('hex')`. This function is used for user passwords, security question answers, and the 2FA pre-image check.

**Security assessment**

MD5 is a fast, non-key-derivation hash with no work factor. Precomputed rainbow tables cover most common passwords. NIST SP 800-63B requires adaptive key-derivation functions (bcrypt, scrypt, PBKDF2, or Argon2) with a work factor tuned so that enumeration of a stolen database takes years, not seconds. Replacing `security.hash()` with a bcrypt or Argon2 call is the minimum remediation; the 2FA pre-image check at `routes/2fa.ts:158` additionally requires migration to a constant-time comparison.

**Relevant findings**

- [T-022](#t-022) — Unsalted MD5 password hashing at `lib/insecurity.ts:43`.
- [T-036](#t-036) — Duplicate finding from data-layer STRIDE confirming the same primitive.

### 7.10 File Parser and Outbound Request Controls

**Verdict:** 🔴 Unsafe

**Controls covered:** [7.10.1 XML Parser Hardening (libxmljs2)](#7101-xml-parser-hardening-libxmljs2), [7.10.2 Archive Extraction (unzipper)](#7102-archive-extraction-unzipper), [7.10.3 Outbound Request Validation (SSRF)](#7103-outbound-request-validation-ssrf)

**Implemented controls:** `multer@1.4.5-lts.1` for multipart form parsing; `sanitize-filename@1.6.3` for uploaded file names; file-size limits applied by multer

**Assessment:** The file upload surface is the most dangerous attack boundary in the application. XML processing is explicitly configured with external entity resolution enabled. Archive extraction performs a path check that is bypassable on Windows-style paths. The profile image URL upload fetches arbitrary attacker-controlled URLs with no allowlist, blocklist, redirect-following limit, or DNS rebinding protection.

<a id="7101-xml-parser-hardening-libxmljs2"></a>

#### 7.10.1 XML Parser Hardening (libxmljs2)

**Status:** 🔴 Unsafe — `noent: true` is passed to `libxmljs2.parseXml()`, enabling external entity resolution (XXE).

`routes/fileUpload.ts:83` receives multipart XML uploads and parses them with `libxmljs2.parseXml(data, { noblanks: true, noent: true, nocdata: true })`. The `noent: true` option instructs `libxmljs2` to resolve external entity references, including `file://` and `http://` URIs in `DOCTYPE` declarations.

**Security assessment**

An attacker submits an XML file with a `DOCTYPE` that references `file:///etc/passwd`. The parser fetches and inlines the file content, which is then returned in the parsed output. The same technique works for `http://` entity references, making this endpoint a second SSRF vector on top of the profile image URL upload. The upload endpoint requires no authentication ([T-018](#t-018)), so this is unauthenticated XXE and SSRF.

The parser configuration at `routes/fileUpload.ts:83`:

```ts
const parsed = libxml.parseXml(data, {
  noblanks: true,
  noent: true,    // enables external entity resolution
  nocdata: true
})
```

**Relevant findings**

- [T-010](#t-010) — XXE via `libxmljs2` with `noent:true` on the unauthenticated upload endpoint.
- [T-046](#t-046) — XML/YAML bomb DoS at the same endpoint; billion-laughs entity expansion causes event-loop exhaustion.

<a id="7102-archive-extraction-unzipper"></a>

#### 7.10.2 Archive Extraction (unzipper)

**Status:** 🔴 Unsafe — the path-containment check at `routes/fileUpload.ts:45` is bypassable on Windows-style paths, allowing Zip Slip arbitrary file writes.

`routes/fileUpload.ts` accepts `.zip` files and extracts them using `unzipper`. Before writing each entry, `routes/fileUpload.ts:45` checks that the resolved path starts with the expected base directory. The check uses `path.join()` without `path.normalize()` on Windows, allowing backslash-separated paths to escape the intended extraction directory.

**Security assessment**

A specially crafted ZIP archive containing an entry named `../../server.ts` (or a Windows variant with backslashes) writes the attacker-supplied content over an arbitrary file in the server's working directory. On the container as deployed, this can overwrite application source files or write to arbitrary locations accessible to the Node.js process UID.

**Relevant findings**

- [T-014](#t-014) — Zip Slip arbitrary file write via flawed path-containment check at `routes/fileUpload.ts:45`.

<a id="7103-outbound-request-validation-ssrf"></a>

#### 7.10.3 Outbound Request Validation (SSRF)

**Status:** 🔴 Missing — `routes/profileImageUrlUpload.ts:24` fetches a user-supplied URL with no validation.

`routes/profileImageUrlUpload.ts:24` calls `const response = await fetch(url)` where `url = req.body.imageUrl` is taken directly from the request body. No protocol allowlist, no IP blocklist, no private-range exclusion, and no redirect-following limit is applied.

**Security assessment**

An attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDSv1) or `http://localhost:3000/rest/admin/application-configuration` as the `imageUrl`. The server fetches the target, and the response content is stored as the user's profile image (or returned in error detail). This allows reading any HTTP resource accessible from the container's network namespace including internal metadata services and private IP ranges.

**Relevant findings**

- [T-039](#t-039) — Server-side request forgery at `routes/profileImageUrlUpload.ts:24`.
- [T-035](#t-035) — Unauthenticated public exposure of the encryption key directory at `server.ts:277`.
- [T-038](#t-038) — Unauthenticated FTP and encryption key directory listing at `server.ts:269`.
- [T-040](#t-040) — Unauthenticated exposure of encryption keys and JWT material at `server.ts:278`.
- [T-041](#t-041) — Unauthenticated log file disclosure via user-controlled filename at `routes/logfileServer.ts:14`.

### 7.11 Operations Runtime and Supply Chain Controls

**Verdict:** 🟠 Weak

**Controls covered:** [7.11.1 Dependency Management](#7111-dependency-management), [7.11.2 Container Security](#7112-container-security), [7.11.3 CI/CD Pipeline Security](#7113-cicd-pipeline-security), [7.11.4 Audit Logging](#7114-audit-logging)

**Implemented controls:** CodeQL SAST in `.github/workflows/codeql-analysis.yml`; distroless runtime image (`gcr.io/distroless/nodejs24-debian12`); non-root UID 65532; Morgan combined-format access logging; CycloneDX SBOM generation in `Dockerfile`

**Assessment:** Runtime container security is the strongest control layer in the application: distroless image and non-root UID together prevent most post-exploitation persistence. Build and supply chain controls are weak: no lockfile, critically outdated JWT libraries, unpinned action references, and postinstall scripts executing as root during the Docker build. Audit logging covers access patterns but not security events.

<a id="7111-dependency-management"></a>

#### 7.11.1 Dependency Management

**Status:** 🔴 Unsafe — lockfile is disabled, critical JWT libraries are decades-old versions, and no automated update tooling is configured.

`.npmrc:1` sets `package-lock=false`, disabling lockfile generation. `package.json` declares `express-jwt@0.1.3` (current: `8.4.1`) and `jsonwebtoken@0.4.0` (current: `9.0.2`) — both are pinned to versions with known security issues and are missing a decade of security patches. `.github/dependabot.yml` exists but does not cover the full dependency graph.

**Security assessment**

Three independent supply-chain weaknesses compound:

- No lockfile means every `npm install` resolves the latest satisfying semver version for each transitive dependency. A compromised transitive package can be introduced silently.
- `express-jwt@0.1.3` lacks the mandatory `algorithms` parameter added in version `5.0.0`, which is the root cause of the `alg:none` bypass ([T-006](#t-006)).
- Dependabot covers only a subset of ecosystems in `.github/dependabot.yml` ([T-061](#t-061)), leaving gaps.

**Relevant findings**

- [T-023](#t-023) — Disabled lockfile enforcement allows dependency substitution via `.npmrc:1`.
- [T-033](#t-033) — `package-lock.json` disabled; lockfile integrity not enforced.
- [T-034](#t-034) — Docker base image not digest-pinned at `Dockerfile:1` and `Dockerfile:23`.
- [T-061](#t-061) — Dependabot ecosystem coverage incomplete.

<a id="7112-container-security"></a>

#### 7.11.2 Container Security

**Status:** 🟡 Partial — distroless runtime and non-root UID are strong positive controls; base images are tag-pinned without digest, and no `HEALTHCHECK` is defined.

The production `Dockerfile` uses a multi-stage build: the build stage is `node:24-alpine` and the runtime stage switches to `gcr.io/distroless/nodejs24-debian12` running as UID 65532. The distroless image contains no shell, no package manager, and no debugging tools, substantially limiting post-exploitation capability.

**Security assessment**

- Distroless + non-root UID 65532 are the application's strongest runtime controls. An attacker who achieves RCE via `eval()` or the notevil escape cannot spawn a shell, install tools, or escalate to root through standard shell tricks.
- `FROM node:24` at `Dockerfile:1` and `FROM gcr.io/distroless/nodejs24-debian12` at `Dockerfile:23` use mutable tags. An upstream image mutation (tag reassignment) would silently change the build content at next pull.
- No `HEALTHCHECK` instruction is defined, so container orchestrators cannot detect a degraded or exploited instance through the standard health mechanism.

**Relevant findings**

- [T-034](#t-034) — Docker base image not digest-pinned; tag mutation enables silent supply-chain substitution.
- [T-064](#t-064) — Missing `HEALTHCHECK` instruction in `Dockerfile`.

<a id="7113-cicd-pipeline-security"></a>

#### 7.11.3 CI/CD Pipeline Security

**Status:** 🟠 Weak — CodeQL SAST is a positive control; GitHub Actions workflows lack `permissions:` declarations and use mutable action tags.

`.github/workflows/ci.yml` runs CodeQL static analysis on every push and pull request. `.github/workflows/release.yml` builds and publishes the Docker image. Neither workflow file includes a top-level `permissions:` block, meaning the `GITHUB_TOKEN` inherits write-all permissions for the repository.

**Security assessment**

Three independent pipeline weaknesses:

- Missing `permissions: contents: read` at `ci.yml` and `release.yml` ([T-031](#t-031)) means any third-party action in the workflow can write to the repository, create releases, or modify pages.
- Third-party actions referenced as `@v2` and `@v3` mutable tags ([T-032](#t-032), [T-017](#t-017)) can be updated by the action author to inject malicious steps without the consumer's knowledge.
- `npm install --unsafe-perm` in `Dockerfile:5` ([T-024](#t-024)) runs postinstall scripts as root during the build, giving any malicious postinstall hook full container access at build time.

**Relevant findings**

- [T-017](#t-017) — Unpinned GitHub Action tag reference in `codeql-analysis.yml:23`.
- [T-024](#t-024) — Unsafe postinstall hook execution during Docker build at `Dockerfile:5`.
- [T-029](#t-029) — `Dockerfile:5` uses `--unsafe-perm` flag.
- [T-030](#t-030) — Hardcoded deployment email in public workflow at `ci.yml:342`.
- [T-031](#t-031) — GitHub Actions workflow missing top-level `permissions` block.
- [T-032](#t-032) — Third-party GitHub Action not pinned to a commit SHA.
- [T-059](#t-059) — Container images published without signing or provenance attestation.
- [T-060](#t-060) — Untrusted npm install/postinstall scripts enabled.
- [T-063](#t-063) — Archived action dependency in release pipeline at `release.yml:66`.

<a id="7114-audit-logging"></a>

#### 7.11.4 Audit Logging

**Status:** 🟡 Partial — Morgan HTTP access logging covers request patterns; no structured security-event log records authentication failures, privilege actions, or authorization denials.

Morgan combined-format access logging is configured in `server.ts` via `app.use(morgan('combined'))`. Every HTTP request and response status is written to the access log. The log is served back via `routes/logfileServer.ts` with a user-controlled filename parameter.

**Security assessment**

Access logs record the fact of each request but not its security significance. Authentication failures, successful brute-force attempts, IDOR accesses, and privilege escalations are indistinguishable from normal traffic in the combined-format log. An attacker can exfiltrate data via IDOR for hours without triggering any alert. Additionally, `routes/logfileServer.ts:14` accepts a caller-supplied filename and reads from the `logs/` directory, creating a path traversal risk where an authenticated user could read log files outside the intended directory.

**Relevant findings**

- [T-026](#t-026) — Missing structured security audit log at `server.ts:338`.
- [T-041](#t-041) — Unauthenticated log file disclosure at `routes/logfileServer.ts:14`.
- [T-054](#t-054) — No authentication event audit logging at `routes/login.ts:19`.
- [T-055](#t-055) — Missing structured audit log for B2B order execution at `routes/b2bOrder.ts:16`.
- [T-056](#t-056) — No audit logging for data write operations at `models/index.ts:39`.
- [T-057](#t-057) — No audit log on unauthenticated file upload or URL-fetch operations.

### 7.12 Real-time and Not Applicable Controls

**Verdict:** 🟡 Partial

**Controls covered:** [7.12.1 WebSocket Security (Socket.IO)](#7121-websocket-security-socketio)

**Implemented controls:** `Socket.IO` 3.1.2 with connection-level JWT auth middleware registered in `lib/startup/registerWebsocketEvents.ts`; structured event handler dispatch

**Assessment:** `Socket.IO` is present and used for the live chat feature and CTF challenge notification system. Connection establishment passes through JWT verification middleware. Per-message re-validation is absent, creating a TOCTOU window where a revoked or expired token can continue interacting via a persistent socket connection.

<a id="7121-websocket-security-socketio"></a>

#### 7.12.1 WebSocket Security (`Socket.IO`)

**Status:** 🟡 Partial — connection-level auth is present; per-message re-validation and rate limiting are absent.

`lib/startup/registerWebsocketEvents.ts:24` registers a connection handler that validates the JWT on the initial WebSocket handshake using the same `express-jwt`-derived middleware as the REST API. Once connected, individual event handlers at lines 34 and 41 do not re-validate the token on each message. CTF flag notification at line 30 broadcasts the flag to all connected clients on the `ctfFlag` event without scoping to the authenticated owning user.

**Security assessment**

Three weaknesses in the WebSocket surface:

- **TOCTOU gap**: A token revoked after connection (e.g., user logs out, admin invalidates session) continues to receive and send events for the full lifetime of the WebSocket connection. After the 6-hour expiry the JWT exp check fails on reconnect, but the open connection persists.
- **CTF flag broadcast** ([T-042](#t-042)): The `challengeSolved` event broadcasts the solved flag to all connected sockets rather than only to the socket associated with the solving user.
- **Rate limiting absent** ([T-047](#t-047)): `lib/startup/registerWebsocketEvents.ts:20` accepts unlimited concurrent connections without throttling.
- **ReDoS** ([T-062](#t-062)): An unanchored regex at `registerWebsocketEvents.ts:47` is evaluated against attacker-controlled WebSocket message data; a crafted input causes catastrophic backtracking.

**Relevant findings**

- [T-019](#t-019) — Unauthenticated WebSocket channel at `registerWebsocketEvents.ts:24`.
- [T-042](#t-042) — Unauthenticated CTF flag broadcast on WebSocket connect at `registerWebsocketEvents.ts:30`.
- [T-047](#t-047) — Unbounded WebSocket connection acceptance without rate limiting at `registerWebsocketEvents.ts:20`.
- [T-062](#t-062) — ReDoS via unanchored regex on attacker-controlled WebSocket data at `registerWebsocketEvents.ts:47`.

### 7.13 Defense-in-Depth Summary

OWASP Juice Shop has no functioning defense-in-depth by design. The two positive runtime controls — distroless container image and non-root UID — are the strongest individual protections in the application. They prevent most post-exploitation persistence and privilege escalation within the container environment. CodeQL SAST in the CI pipeline provides a third positive layer, though it has not flagged the intentional vulnerabilities (expected, given they are known training artifacts).

The structural defect that cascades furthest is the hardcoded RSA private key at `lib/insecurity.ts:23`. It simultaneously defeats authentication (JWT forgery), authorization (arbitrary `role` claim), session management (token theft is permanent), and the B2B API trust boundary. A single remediation — moving the private key to a managed secret store and upgrading `express-jwt` to version `8.x` with an `algorithms: ['RS256']` restriction — closes more attack surface than any other single change. The second-highest-leverage repair is replacing `security.hash()` with bcrypt or Argon2, which breaks the chain from SQL injection → credential dump → immediate recovery.

<!-- enriched:standard -->
