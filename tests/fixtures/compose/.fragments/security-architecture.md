## 7. Security Architecture

This chapter is organized by security-control category. The fixture keeps the prose compact so compose and render-property tests exercise the current §7 contract without depending on legacy headings.

### 7.1 Security Control Overview

| Control category | Verdict | Main reason |
|---|---|---|
| [7.2 Identity and Authentication Controls](#72-identity-and-authentication-controls) | Weak | JWT issuance and MFA exist, but key handling and enforcement have gaps. |
| [7.3 Session and Token Controls](#73-session-and-token-controls) | Weak | Browser token storage and revocation are weak. |
| [7.4 Authorization Controls](#74-authorization-controls) | Weak | Server-side authorization is incomplete. |
| [7.5 Query Construction and Data Access Controls](#75-query-construction-and-data-access-controls) | Unsafe | Raw SQL is still reachable on login and search. |
| [7.6 Input Boundary Validation Controls](#76-input-boundary-validation-controls) | Partial | Validation is per-route rather than centralized. |
| [7.7 Output Encoding and Rendering Controls](#77-output-encoding-and-rendering-controls) | Weak | Angular escaping exists, but sanitizer bypasses remain. |
| [7.8 Browser and Cross-Origin Controls](#78-browser-and-cross-origin-controls) | Partial | Browser headers exist only in limited form. |
| [7.9 Cryptography Secrets and Data Protection](#79-cryptography-secrets-and-data-protection) | Unsafe | Signing keys are committed to source. |
| [7.10 File Parser and Outbound Request Controls](#710-file-parser-and-outbound-request-controls) | - | No file-parser or outbound-request finding is in this fixture. |
| [7.11 Operations Runtime and Supply Chain Controls](#711-operations-runtime-and-supply-chain-controls) | Partial | Runtime hardening exists, but dependency posture is incomplete. |
| [7.12 Real-time and Not Applicable Controls](#712-real-time-and-not-applicable-controls) | - | No real-time, AI, GraphQL, or gRPC surface is in this fixture. |
| [7.13 Defense-in-Depth Summary](#713-defense-in-depth-summary) | Weak | Controls are present but concentrated in one application layer. |

### 7.2 Identity and Authentication Controls

**Verdict:** Weak

**Controls covered:** [JWT-based Authentication](#jwt-based-authentication), [TOTP Two-Factor Authentication](#totp-two-factor-authentication).

**Implemented controls:** RS256 JWT issuance and otplib-backed TOTP are present.

**Assessment:** Password login issues JWTs and the standard login path can enroll TOTP. Key handling and verification remain weak enough that authentication cannot be treated as a strong boundary.

<a id="jwt-based-authentication"></a>
#### JWT-based Authentication

JWT-based login signs session tokens for authenticated users and is the primary identity handoff between the API and browser client.

**Status:** Weak

**Security assessment**

The fixture signs JWTs with a committed RSA key and does not show robust key rotation or algorithm hardening.

**Relevant findings**

- Hardcoded RSA private key.

<a id="totp-two-factor-authentication"></a>
#### TOTP Two-Factor Authentication

TOTP adds a second login factor on the standard authentication path and uses otplib for token generation and verification.

**Status:** Partial

**Security assessment**

The control exists, but the fixture does not establish uniform enforcement across all authentication flows.

**Relevant findings**

- No dedicated finding routed in this assessment.

### 7.3 Session and Token Controls

**Verdict:** Weak

**Controls covered:** [Browser Token Storage](#browser-token-storage).

**Implemented controls:** JWT bearer tokens are used after login.

**Assessment:** The session boundary depends on browser-held JWTs and lacks a clear revocation story in this fixture.

<a id="browser-token-storage"></a>
#### Browser Token Storage

The browser sends the JWT back to the API for authenticated requests.

**Status:** Weak

**Security assessment**

Token storage and lifecycle controls are too thin to contain XSS or key-disclosure scenarios.

**Relevant findings**

- No dedicated session finding routed in this assessment.

### 7.4 Authorization Controls

**Verdict:** Weak

**Controls covered:** [Route Authorization](#route-authorization).

**Implemented controls:** Angular route guards and API role checks exist in limited paths.

**Assessment:** The fixture relies too much on client-side route behavior and does not prove object-level authorization on server-side routes.

<a id="route-authorization"></a>
#### Route Authorization

Route authorization is expected to restrict privileged API calls to the right user or role.

**Status:** Weak

**Security assessment**

Server-side enforcement is incomplete in the fixture, so browser controls do not form a reliable authorization boundary.

**Relevant findings**

- No dedicated authorization finding routed in this assessment.

### 7.5 Query Construction and Data Access Controls

**Verdict:** Unsafe

**Controls covered:** [Parameterized Database Access](#parameterized-database-access).

**Implemented controls:** Sequelize is used for most CRUD queries.

**Assessment:** Login and product search still build raw SQL strings, so the data-access layer has a defeated control exactly where public input reaches the database.

<a id="parameterized-database-access"></a>
#### Parameterized Database Access

Parameterized database access keeps user-controlled values out of SQL syntax.

**Status:** Unsafe

**Security assessment**

The ORM is present, but raw SQL construction remains on sensitive routes.

**Relevant findings**

- SQL injection in product search.
- SQL injection in login.

### 7.6 Input Boundary Validation Controls

**Verdict:** Partial

**Controls covered:** [Validation Approach](#validation-approach).

**Implemented controls:** Some route handlers validate expected fields before persistence.

**Assessment:** Validation is fragmented and does not consistently sit at the request boundary.

<a id="validation-approach"></a>
#### Validation Approach

The validation approach should reject malformed or unexpected user input before it reaches business logic or persistence.

**Status:** Partial

**Security assessment**

The fixture shows per-route checks, but no centralized schema strategy that would make parser, request-size, and business-rule boundaries consistent.

**Relevant findings**

- No dedicated validation finding routed in this assessment.

### 7.7 Output Encoding and Rendering Controls

**Verdict:** Weak

**Controls covered:** [Output Encoding](#output-encoding).

**Implemented controls:** Angular template escaping protects standard interpolation paths.

**Assessment:** Direct sanitizer bypass calls keep exploitable rendering paths alive despite the framework default.

<a id="output-encoding"></a>
#### Output Encoding

Output encoding prevents stored content from becoming executable browser content.

**Status:** Weak

**Security assessment**

Framework escaping is present, but trusted-HTML bypasses undercut that protection.

**Relevant findings**

- Persistent XSS via bypassSecurityTrustHtml.

### 7.8 Browser and Cross-Origin Controls

**Verdict:** Partial

**Controls covered:** [Browser Security Headers](#browser-security-headers).

**Implemented controls:** Some browser-facing header behavior exists through the Node stack.

**Assessment:** The fixture does not establish a complete CSP, CORS, CSRF, and clickjacking posture.

<a id="browser-security-headers"></a>
#### Browser Security Headers

Browser headers constrain what the client can load, frame, and send cross-origin.

**Status:** Partial

**Security assessment**

The browser policy is present only in limited form and does not compensate for the rendering weaknesses.

**Relevant findings**

- No dedicated browser-policy finding routed in this assessment.

### 7.9 Cryptography Secrets and Data Protection

**Verdict:** Unsafe

**Controls covered:** [JWT Signing Key Management](#jwt-signing-key-management).

**Implemented controls:** RS256 is used for token signing.

**Assessment:** The cryptographic primitive is stronger than the way it is operated; a committed signing key collapses the trust boundary.

<a id="jwt-signing-key-management"></a>
#### JWT Signing Key Management

JWT signing key management keeps token-forging capability out of the repository and runtime logs.

**Status:** Unsafe

**Security assessment**

The RSA key material is part of the fixture source, so anyone with repository read access can mint tokens offline.

**Relevant findings**

- Hardcoded RSA private key.

### 7.10 File Parser and Outbound Request Controls

**Verdict:** Not applicable

_Not applicable for this fixture - no file-parser or outbound-request finding is routed to this category._

### 7.11 Operations Runtime and Supply Chain Controls

**Verdict:** Partial

**Controls covered:** [Container Base Image](#container-base-image).

**Implemented controls:** The runtime image is represented as a hardened Node container baseline.

**Assessment:** Runtime hardening is a useful layer, but it does not offset application-layer injection, signing-key, or rendering defects.

<a id="container-base-image"></a>
#### Container Base Image

The container base image reduces runtime package and operating-system exposure for the service process.

**Status:** Adequate

**Security assessment**

The positive runtime signal is narrow and should be treated as defense in depth, not as a compensating control for the application weaknesses.

**Relevant findings**

- No dedicated runtime finding routed in this assessment.

### 7.12 Real-time and Not Applicable Controls

**Verdict:** Not applicable

_Not applicable - no real-time / WebSocket findings routed to this category, and no AI/LLM, GraphQL, or gRPC surface is represented in this fixture._

### 7.13 Defense-in-Depth Summary

**Verdict:** Weak

The fixture has several useful individual controls: framework output escaping, JWT signing, TOTP enrollment, ORM usage on common CRUD paths, and a hardened container baseline. Those controls are not independent enough to stop the same public-input flaws from reaching authentication, query construction, and browser rendering paths.

Layered defense would improve most by fixing raw SQL construction, moving signing material out of source, enforcing server-side authorization, and removing trusted-HTML bypasses. Those repairs would give the existing controls room to act as backstops instead of single points of failure.
