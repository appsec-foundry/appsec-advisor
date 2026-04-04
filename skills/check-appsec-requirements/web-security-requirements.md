# Web Application Security Requirements

This file defines baseline security requirements for web applications.
Each requirement is tagged with `[SEC-<CATEGORY>-<NUMBER>]` and can be verified by the
`/appsec-plugin:check-appsec-requirements` skill.

**Categories:**
| Prefix | Domain |
|--------|--------|
| `SEC-INV` | Input Validation |
| `SEC-ENC` | Output Encoding |
| `SEC-AUTH` | Authentication |
| `SEC-AUTHZ` | Authorization |
| `SEC-DATA` | Data Security |
| `SEC-ERR` | Error Handling & Logging |
| `SEC-CSP` | Frontend Security |
| `SEC-HARD` | Hardening |

---

## Input Validation

`[SEC-INV-1]` All user-supplied input must be validated server-side against an explicit allowlist or schema before use. Client-side validation alone is insufficient.

`[SEC-INV-2]` Input length must be bounded. Every field must enforce a maximum length appropriate to its purpose; unbounded strings must not be accepted.

`[SEC-INV-3]` Numeric, date, and enum inputs must be type-checked and range-validated before processing.

`[SEC-INV-4]` File uploads must validate MIME type and file extension server-side (not from the Content-Type header alone). Uploaded content must be stored outside the web root and served with a safe Content-Disposition header.

`[SEC-INV-5]` URL and redirect parameters must be validated against an allowlist of permitted destinations. Open redirects must not be possible.

`[SEC-INV-6]` Path components used in file or resource access must be canonicalized and validated to prevent path traversal (e.g. `../` sequences).

`[SEC-INV-7]` XML and JSON inputs must be parsed with external entity processing disabled (no XXE). JSON schema validation must be applied where structured input is expected.

`[SEC-INV-8]` Batch or bulk operations must enforce a maximum item count to prevent amplification attacks.

---

## Output Encoding

`[SEC-ENC-1]` All data rendered into HTML must be context-sensitively encoded (HTML entity encoding for HTML context, JavaScript encoding for script context, URL encoding for URL context).

`[SEC-ENC-2]` Database queries must use parameterized statements or a safe ORM abstraction. Dynamic SQL string concatenation with user input is prohibited.

`[SEC-ENC-3]` OS command execution must not incorporate user-supplied input directly. If shell commands are required, arguments must be passed as an array (not interpolated into a shell string).

`[SEC-ENC-4]` LDAP, XPath, and NoSQL query inputs must be escaped or parameterized to prevent injection.

`[SEC-ENC-5]` Template engines must auto-escape output by default. Raw/unescaped output directives (e.g. `|safe`, `v-html`, `dangerouslySetInnerHTML`) must not be used with untrusted data.

`[SEC-ENC-6]` HTTP response headers written from user-controlled values must be sanitized to prevent header injection (no CR/LF in header values).

---

## Authentication

`[SEC-AUTH-1]` All non-public endpoints must require authentication. Authentication state must be checked server-side on every request; client-side state alone is not sufficient.

`[SEC-AUTH-2]` Passwords must be hashed with a modern adaptive algorithm (bcrypt, scrypt, or Argon2) with an appropriate work factor. MD5, SHA-1, and unsalted hashes are prohibited.

`[SEC-AUTH-3]` Login responses must not distinguish between an unknown username and a wrong password. Error messages must be generic to prevent account enumeration.

`[SEC-AUTH-4]` Brute-force protection must be in place on all authentication endpoints: rate limiting, exponential back-off, or account lockout after a configurable number of failed attempts.

`[SEC-AUTH-5]` Session tokens and bearer tokens must be generated with a cryptographically secure random source and must have sufficient entropy (≥ 128 bits).

`[SEC-AUTH-6]` Tokens must have a defined expiry. Short-lived access tokens (≤ 15 minutes for sensitive operations) must be used with a refresh token mechanism.

`[SEC-AUTH-7]` Multi-factor authentication must be supported and enforced for privileged accounts and administrative functions.

`[SEC-AUTH-8]` Password reset and account recovery flows must use time-limited, single-use tokens delivered out-of-band (email, SMS). Security questions are prohibited.

`[SEC-AUTH-9]` OAuth 2.0 / OIDC implementations must validate `state` and `nonce` parameters and must use PKCE for public clients.

---

## Authorization

`[SEC-AUTHZ-1]` Access control decisions must be enforced server-side on every request. Authorization logic must not rely solely on UI visibility or client-supplied role claims.

`[SEC-AUTHZ-2]` Every resource access must verify that the authenticated user owns or has explicit permission to access that specific resource (no IDOR). Sequential or guessable resource identifiers must not be used as the sole access control mechanism.

`[SEC-AUTHZ-3]` Privilege separation must be enforced: regular users must not be able to access administrative endpoints or functions even if they know the URL.

`[SEC-AUTHZ-4]` The principle of least privilege must be applied. Users, service accounts, and API keys must be granted only the minimum permissions required for their function.

`[SEC-AUTHZ-5]` Permission checks must be applied consistently across all access paths to the same resource (REST endpoint, GraphQL resolver, background job, internal API).

`[SEC-AUTHZ-6]` Sensitive operations (account deletion, fund transfer, privilege escalation) must require re-authentication or step-up authentication even within an active session.

`[SEC-AUTHZ-7]` All access control failures must be logged with sufficient context (user, resource, action, timestamp) for incident investigation.

---

## Data Security

`[SEC-DATA-1]` All data in transit must be protected with TLS 1.2 or higher. TLS 1.0 and 1.1 must be disabled. HTTP must redirect to HTTPS.

`[SEC-DATA-2]` Sensitive data at rest (PII, credentials, financial data, health records) must be encrypted. Encryption keys must be managed separately from the encrypted data (not hardcoded, not in the same datastore).

`[SEC-DATA-3]` Secrets (API keys, database passwords, private keys, tokens) must never be hardcoded in source code or committed to version control. They must be loaded from environment variables, a secrets manager (Vault, AWS Secrets Manager, etc.), or equivalent.

`[SEC-DATA-4]` PII and sensitive fields must not be written to application logs, error messages, or analytics pipelines unless explicitly required and protected.

`[SEC-DATA-5]` Credit card numbers, social security numbers, and similar regulated data must be masked or tokenized before storage. Full values must not be stored unless strictly required and compliant with applicable regulations (PCI-DSS, etc.).

`[SEC-DATA-6]` Cryptographic algorithms must be current and approved: AES-256 for symmetric encryption, RSA-2048+ or ECDSA P-256+ for asymmetric, SHA-256+ for hashing. MD5, DES, RC4, and ECB mode are prohibited.

`[SEC-DATA-7]` A data retention policy must be defined and enforced. Data that is no longer needed must be securely deleted; retention periods must comply with applicable regulations.

`[SEC-DATA-8]` Database connections must use the minimum required privilege account. The application must not connect to the database with a DBA or root account.

---

## Error Handling & Logging

`[SEC-ERR-1]` Application errors must not expose stack traces, internal file paths, database query details, or framework version information to end users. Generic error messages must be shown; full details logged server-side only.

`[SEC-ERR-2]` All authentication and authorization events must be logged: successful logins, failed login attempts, logouts, password changes, privilege escalations, and access denials.

`[SEC-ERR-3]` Security-relevant application events must be logged: input validation failures, unexpected data access patterns, configuration changes, and bulk data exports.

`[SEC-ERR-4]` Log entries must include: timestamp (UTC), event type, user identity (or session ID), source IP address, affected resource, and outcome. Personally identifiable data in logs must be minimized.

`[SEC-ERR-5]` Logs must be written to an append-only destination that the application cannot modify or delete. Log integrity must be protected against tampering.

`[SEC-ERR-6]` Error handling code must not silently swallow exceptions that indicate security failures. Unexpected exceptions must be caught at the boundary, logged, and surfaced as a safe generic error.

`[SEC-ERR-7]` A global exception handler must be in place to catch unhandled errors and return a controlled response, preventing raw framework error pages from reaching clients.

---

## Frontend Security

`[SEC-CSP-1]` A Content Security Policy (CSP) header must be present on all HTML responses. The policy must prohibit `unsafe-inline` and `unsafe-eval` for scripts. A report URI should be configured.

`[SEC-CSP-2]` The `X-Frame-Options: DENY` or `SAMEORIGIN` header (or equivalent CSP `frame-ancestors`) must be set to prevent clickjacking.

`[SEC-CSP-3]` The `X-Content-Type-Options: nosniff` header must be set on all responses to prevent MIME-type sniffing.

`[SEC-CSP-4]` The `Referrer-Policy` header must be set to `strict-origin-when-cross-origin` or stricter to limit referrer information leakage.

`[SEC-CSP-5]` The `Permissions-Policy` header must be set to disable browser features not required by the application (camera, microphone, geolocation, etc.).

`[SEC-CSP-6]` All state-mutating operations must be protected against Cross-Site Request Forgery (CSRF) using synchronizer tokens, double-submit cookies, or the `SameSite=Strict`/`Lax` cookie attribute.

`[SEC-CSP-7]` Session cookies must be set with `HttpOnly` (not accessible via JavaScript), `Secure` (HTTPS only), and `SameSite=Strict` or `Lax` attributes.

`[SEC-CSP-8]` Subresource Integrity (SRI) hashes must be applied to all externally-hosted scripts and stylesheets (`<script integrity="...">`, `<link integrity="...">`).

`[SEC-CSP-9]` DOM-based XSS sinks (`innerHTML`, `document.write`, `eval`, `setTimeout` with strings) must not be used with untrusted data. Safe DOM APIs (`textContent`, `createElement`) must be used instead.

`[SEC-CSP-10]` Third-party JavaScript must be reviewed and explicitly approved before inclusion. The supply-chain risk of each dependency must be assessed.

---

## Hardening

`[SEC-HARD-1]` Debug mode, verbose error reporting, and development tooling must be disabled in production environments. Feature flags for development features must default to off.

`[SEC-HARD-2]` Default credentials (admin/admin, admin/password, etc.) must be changed or removed before deployment. There must be no accounts with empty passwords.

`[SEC-HARD-3]` Unused endpoints, routes, HTTP methods, and API versions must be disabled or removed. The application must return 404 or 405 for undeclared methods rather than processing them.

`[SEC-HARD-4]` The `Server`, `X-Powered-By`, and `X-AspNet-Version` response headers must be suppressed to avoid advertising framework and version information.

`[SEC-HARD-5]` HTTP Strict Transport Security (HSTS) must be set with a `max-age` of at least 1 year and must include `includeSubDomains`. Preloading is recommended.

`[SEC-HARD-6]` Dependency versions must be pinned (lock files committed). Automated dependency scanning (SCA) must run in CI and must block builds with known critical or high CVEs.

`[SEC-HARD-7]` Containers must run as a non-root user. The root filesystem must be read-only where possible. Capabilities must be dropped to the minimum required set.

`[SEC-HARD-8]` Infrastructure-as-code and deployment manifests must be reviewed for insecure defaults: open security groups, public S3 buckets, unauthenticated endpoints, excessive IAM permissions.

`[SEC-HARD-9]` Static Application Security Testing (SAST) must run on every pull request. Findings of high severity must block merge.

`[SEC-HARD-10]` Secret scanning must run in CI to detect accidentally committed credentials. Pre-commit hooks should prevent secrets from reaching version control.

`[SEC-HARD-11]` Rate limiting must be applied to all public-facing endpoints, with stricter limits on authentication, password reset, and resource-intensive operations.

`[SEC-HARD-12]` Dependency license compliance must be verified. Copyleft licenses (GPL, AGPL) must not be introduced into commercial products without legal review.
