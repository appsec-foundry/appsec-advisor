## 6. Security Architecture

This chapter is organized by security-control category. The architecture section avoids artificial control IDs and finding-ID columns in overview tables. Findings are listed only where the affected control is described.

_§6 schema v2 (13-section control-category layout). Cataloged controls: 23 total — 0 adequate, 2 partial, 3 weak, 6 unsafe, 12 missing. Linked threats: 13._

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

### 6.1 Security Control Overview

<!-- §6.1 MECHANICAL-FROZEN — DO NOT EDIT (overview table is pregenerator-owned) -->

| Control category | Verdict | Main reason |
|---|---|---|
| [6.2 Identity and Authentication Controls](#62-identity-and-authentication-controls) | 🔴 Unsafe | Catalogued controls are present but defeated (e.g. Partner API Key Authentication, Route Authentication Enforcement). |
| [6.3 Session and Token Controls](#63-session-and-token-controls) | 🔴 Unsafe | Catalogued controls are present but defeated (e.g. Session Token Validation (JWT Based)). |
| [6.4 Authorization Controls](#64-authorization-controls) | 🔴 Unsafe | 3 routed findings; catalogued controls are present but defeated (e.g. Object-Level Ownership Check (BOLA/IDOR), Tenant Identity Validation). |
| [6.5 Query Construction and Data Access Controls](#65-query-construction-and-data-access-controls) | 🔴 Unsafe | 2 routed findings; catalogued controls are present but defeated (e.g. SQL Parameterized Queries). |
| [6.6 Input Boundary Validation Controls](#66-input-boundary-validation-controls) | 🔴 Missing | 1 routed finding; required controls not in place (e.g. Schema and Allowlist Input Validation). |
| [6.7 Output Encoding and Rendering Controls](#67-output-encoding-and-rendering-controls) | — | No controls or findings routed to this category. |
| [6.8 Browser and Cross-Origin Controls](#68-browser-and-cross-origin-controls) | — | No controls or findings routed to this category. |
| [6.9 Cryptography Secrets and Data Protection](#69-cryptography-secrets-and-data-protection) | 🔴 Unsafe | 1 routed finding; catalogued controls are present but defeated (e.g. JWT Secret Management, Credential and Secret Storage). |
| [6.10 File Parser and Outbound Request Controls](#610-file-parser-and-outbound-request-controls) | 🔴 Missing | 4 routed findings; required controls not in place (e.g. SSRF Egress URL Filtering). |
| [6.11 Operations Runtime and Supply Chain Controls](#611-operations-runtime-and-supply-chain-controls) | 🔴 Missing | 1 routed finding; required controls not in place (e.g. Third-Party CI Action Pinning, Dependency Vulnerability Management). |
| [6.12 Real-time and Not Applicable Controls](#612-real-time-and-not-applicable-controls) | — | No controls or findings routed to this category. |
| [6.13 Defense-in-Depth Summary](#613-defense-in-depth-summary) | — | No controls or findings routed to this category. |

<!-- §6.1 MECHANICAL-FROZEN END -->

### 6.2 Identity and Authentication Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Partner API Key Authentication](#partner-api-key-authentication), [Route Authentication Enforcement](#route-authentication-enforcement).

**Implemented controls:** middleware/partnerAuth.js, routes/partner-api/orders.js:5; server.js:22,34,40,41.

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.2 Identity and Authentication Controls — Registration, password login, OAuth/OIDC adapters, MFA/TOTP, JWT issuance and verification, password reset/change. -->

<!-- §6.2 AUTH-MECHANISMS-FROZEN — deterministic inventory, pregenerator-owned. DO NOT EDIT. -->
**Authentication mechanisms (at a glance).** Every authentication mechanism detected on the application, its effective status, where it is assessed, and its linked findings. Controls are catalogued by domain, so JWT/session handling is assessed under [§6.3 Session and Token Controls](#63-session-and-token-controls) and password hashing under [§6.9 Cryptography Secrets and Data Protection](#69-cryptography-secrets-and-data-protection).

| Mechanism | Status | Assessed in | Findings |
|---|---|---|---|
| User registration | 🔴 Missing | [§6.2](#62-identity-and-authentication-controls) | [F-010](#f-010) — Sensitive REST route registered without authentication middleware — server.js:22 |
| Password login | 🔴 Critical | [§6.2](#62-identity-and-authentication-controls) | [F-001](#f-001) — SQL Injection authentication bypass — server.js:12 |
| Password reset / change | 🔴 Missing | [§6.2](#62-identity-and-authentication-controls) | — |
| JWT / bearer-token session | 🔴 Unsafe | [§6.3](#63-session-and-token-controls) | [F-005](#f-005) — Hardcoded JWT signing key — server.js:9 |

_Also checked, not detected on this codebase: Password storage (hashing), Session-token storage, Multi-factor authentication (TOTP / 2FA), OAuth / OIDC federated login._

<!-- §6.2 AUTH-MECHANISMS-FROZEN END -->

<a id="partner-api-key-authentication"></a>
#### 6.2.1 Partner API Key Authentication

**Status:** 🟡 Partial — Auth mechanism present on partner routes; missing on admin, AI, and debug routes.

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- No dedicated finding routed in this assessment.

<a id="route-authentication-enforcement"></a>
#### 6.2.2 Route Authentication Enforcement

**Status:** 🔴 Unsafe — State-changing and sensitive routes reachable without credentials.

server.js:22,34,40,41

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- No dedicated finding routed in this assessment.

_Additional cataloged controls without a dedicated subsection (no implementation prose and no linked findings): User Registration, Password Reset._

<!-- NARRATIVE_PLACEHOLDER: precede with one sentence ending in `:` then a positive-flow ```mermaid sequenceDiagram``` of the primary flow for this section (for §6.3: JWT/session issuance → browser storage → Bearer presentation → server verification). One diagram for the section satisfies the requirement; per-stage detail stays in the H4 sub-blocks above. -->

### 6.3 Session and Token Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Session Token Validation](#session-token-validation).

**Implemented controls:** server.js:9,14.

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.3 Session and Token Controls — Browser token storage, request propagation, token lifetime, revocation, cookie/session boundary. -->

<a id="session-token-validation"></a><a id="session-token-validation-jwt-based"></a>
#### 6.3.1 Session Token Validation

**Status:** 🔴 Unsafe — Hardcoded JWT secret allows arbitrary token forgery.

server.js:9,14

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- No dedicated finding routed in this assessment.

<!-- NARRATIVE_PLACEHOLDER: precede with one sentence ending in `:` then a positive-flow ```mermaid sequenceDiagram``` of the primary flow for this section (for §6.3: JWT/session issuance → browser storage → Bearer presentation → server verification). One diagram for the section satisfies the requirement; per-stage detail stays in the H4 sub-blocks above. -->

### 6.4 Authorization Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Object-Level Ownership Check](#object-level-ownership-check), [Tenant Identity Validation](#tenant-identity-validation), [Management Endpoint Protection](#management-endpoint-protection).

**Implemented controls:** server.js:17-19; middleware/tenantContext.js:2; server.js:22,41.

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.4 Authorization Controls — Route middleware, role checks, object-level authorization, client-side guards versus server-side enforcement. -->

<a id="object-level-ownership-check"></a><a id="object-level-ownership-check-bolaidor"></a>
#### 6.4.1 Object-Level Ownership Check

**Status:** 🔴 Missing — No ownership check on user record retrieval.

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-009](#f-009)
- [F-010](#f-010)
- [F-011](#f-011)

<a id="tenant-identity-validation"></a>
#### 6.4.2 Tenant Identity Validation

**Status:** 🔴 Unsafe — Tenant identity is caller-asserted; authentication binding absent.

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-009](#f-009)
- [F-010](#f-010)
- [F-011](#f-011)

<a id="management-endpoint-protection"></a>
#### 6.4.3 Management Endpoint Protection

**Status:** 🟡 Partial — Auth and authz status on admin and debug endpoints is unconfirmed.

server.js:22,41

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-009](#f-009)
- [F-010](#f-010)
- [F-011](#f-011)

### 6.5 Query Construction and Data Access Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [SQL Parameterized Queries](#sql-parameterized-queries).

**Implemented controls:** server.js:12,18.

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.5 Query Construction and Data Access Controls — SQL/NoSQL query construction, ORM usage, parameter binding, selector and object ownership boundaries. -->

<a id="sql-parameterized-queries"></a>
#### 6.5.1 SQL Parameterized Queries

**Status:** 🔴 Unsafe — Raw SQL string interpolation at login and user-lookup routes.

server.js:12,18

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-001](#f-001)
- [F-003](#f-003)

### 6.6 Input Boundary Validation Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Validation Approach](#validation-approach), [Schema and Allowlist Input Validation](#schema-and-allowlist-input-validation).

**Implemented controls:** server.js (all routes).

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.6 Input Boundary Validation Controls — Request schemas, parser limits, upload constraints, URL/path validation, business-rule boundaries. -->

<a id="validation-approach"></a>
#### 6.6.1 Validation Approach

**Status:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` / `🟡 Partial` / `🟠 Weak` / `🔴 Unsafe` / `🔴 Missing`, then add one clause stating the bottom line. present-but-broken → Unsafe; never-built → Missing. -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-008](#f-008)

<a id="schema-and-allowlist-input-validation"></a>
#### 6.6.2 Schema and Allowlist Input Validation

**Status:** 🔴 Missing — No schema or allowlist validation applied to any request handler.

server.js (all routes)

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-008](#f-008)

### 6.7 Output Encoding and Rendering Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

**Controls covered:** <!-- NARRATIVE_PLACEHOLDER: list concrete subcontrols as markdown links to H4 headings. -->

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.7 Output Encoding and Rendering Controls — Template escaping, DOM sinks, sanitizer bypasses, HTML rendering contexts. -->

### 6.8 Browser and Cross-Origin Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

**Controls covered:** <!-- NARRATIVE_PLACEHOLDER: list concrete subcontrols as markdown links to H4 headings. -->

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.8 Browser and Cross-Origin Controls — CSP, CORS, CSRF, Helmet/header hardening, browser-side request policy. -->

### 6.9 Cryptography Secrets and Data Protection

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [JWT Secret Management](#jwt-secret-management), [Credential and Secret Storage](#credential-and-secret-storage).

**Implemented controls:** server.js:9; config/insecure-settings.ini:2,5.

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.9 Cryptography Secrets and Data Protection — Signing keys, HMAC/cookie secrets, password storage, data-at-rest protection. -->

<a id="jwt-secret-management"></a>
#### 6.9.1 JWT Secret Management

**Status:** 🔴 Unsafe — JWT secret committed in source; trivially extractable.

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-005](#f-005)

<a id="credential-and-secret-storage"></a>
#### 6.9.2 Credential and Secret Storage

**Status:** 🔴 Unsafe — Database password and auth secret stored in plaintext in committed config file.

config/insecure-settings.ini:2,5

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-005](#f-005)

### 6.10 File Parser and Outbound Request Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [SSRF Egress URL Filtering](#ssrf-egress-url-filtering).

**Implemented controls:** server.js:30.

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.10 File Parser and Outbound Request Controls — Uploads, archives, XML parsing, unsafe interpreters, SSRF, redirects, static or management-surface exposure. -->

<a id="ssrf-egress-url-filtering"></a>
#### 6.10.1 SSRF Egress URL Filtering

**Status:** 🔴 Missing — Attacker-controlled URL passed directly to fetch() with no restriction.

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-002](#f-002)
- [F-006](#f-006)
- [F-007](#f-007)

### 6.11 Operations Runtime and Supply Chain Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Third-Party CI Action Pinning](#third-party-ci-action-pinning), [Dependency Vulnerability Management](#dependency-vulnerability-management), [Automated SCA scanning](#automated-sca-scanning), [Automated dependency updates](#automated-dependency-updates), [Lockfile hygiene](#lockfile-hygiene).

**Implemented controls:** .github/workflows/ci.yml:8-9; package.json.

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.11 Operations Runtime and Supply Chain Controls — Audit logging, runtime/container hardening, dependency determinism, CI workflow permissions, package-install controls. -->

<a id="third-party-ci-action-pinning"></a>
#### 6.11.1 Third-Party CI Action Pinning

**Status:** 🟠 Weak — Actions pinned to mutable v3 tags; commit-SHA pinning absent.

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-012](#f-012)

<a id="dependency-vulnerability-management"></a>
#### 6.11.2 Dependency Vulnerability Management

**Status:** 🟠 Weak — lodash@4.17.10 has known CVEs; no automated dependency scanning evident.

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-012](#f-012)

<a id="automated-sca-scanning"></a>
#### 6.11.3 Automated SCA scanning

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-012](#f-012)

<a id="automated-dependency-updates"></a>
#### 6.11.4 Automated dependency updates

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-012](#f-012)

<a id="lockfile-hygiene"></a>
#### 6.11.5 Lockfile hygiene

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-012](#f-012)

### 6.12 Real-time and Not Applicable Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [LLM Integration Security](#llm-integration-security).

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §6.12 Real-time and Not Applicable Controls — WebSocket/real-time channels plus compact absent-domain statements. -->

<a id="llm-integration-security"></a>
#### 6.12.1 LLM Integration Security

**Status:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` / `🟡 Partial` / `🟠 Weak` / `🔴 Unsafe` / `🔴 Missing`, then add one clause stating the bottom line. present-but-broken → Unsafe; never-built → Missing. -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- No dedicated finding routed in this assessment.

### 6.13 Defense-in-Depth Summary

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. -->

<!-- §6.13 FORMAT — prose-only, NEVER a table. Two short paragraphs: (1) name the individual controls that exist and the strongest positive control if any (e.g. distroless runtime image, RS256 algorithm choice); (2) name which control-boundary repairs would restore layered defense (e.g. parameterized queries, runtime-injected secrets, strict JWT verification). Do NOT emit a Markdown table — `| header |` lines under §6.13 are a contract violation. Do NOT make speculative perimeter-absence claims (`No WAF`, `No firewall`, `No DAM`) — only positive evidence from the recon scan. -->

<!-- NARRATIVE_PLACEHOLDER: §6.13 Defense-in-Depth Summary — Cross-cutting summary of layered controls and residual architecture risk. (prose paragraphs only) -->
