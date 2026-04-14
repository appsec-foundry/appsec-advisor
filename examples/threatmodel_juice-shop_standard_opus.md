# Threat Model — OWASP Juice Shop

> | Field | Value |
> |-------|-------|
> | **Project** | OWASP Juice Shop v19.2.1 |
> | **Repository** | https://github.com/juice-shop/juice-shop |
> | **Team Owner** | OWASP Juice Shop project |
> | **Asset Tier** | Tier 1 (intentionally vulnerable training platform) |
> | **Compliance Scope** | OWASP Top 10, OWASP ASVS |
> | **Deployment** | Node.js monolith · Docker · SQLite in-process |

---

## Changelog

| Version | Date | Mode | Components Analyzed | Summary |
|---------|------|------|---------------------|---------|
| v1 | 2026-04-14 | Full | auth-service, rest-api, frontend-spa, file-processor, data-access | Initial assessment — 30 threats, 23 mitigations |

---

## Table of Contents

1. [Management Summary](#management-summary)
2. [Critical Attack Chain](#critical-attack-chain)
3. [System Overview](#1-system-overview)
4. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Container Architecture](#22-container-architecture)
   - [2.3 Technology Architecture](#23-technology-architecture)
   - [2.4 Security Architecture Assessment](#24-security-architecture-assessment)
5. [Attack Walkthroughs](#3-attack-walkthroughs)
6. [Assets](#4-assets)
7. [Attack Surface](#5-attack-surface)
8. [Trust Boundaries](#6-trust-boundaries)
9. [Identified Security Controls](#7-identified-security-controls)
10. [Threat Register](#8-threat-register)
11. [Mitigation Register](#9-mitigation-register)
12. [Out of Scope](#10-out-of-scope)
13. [Appendix: Run Statistics](#appendix-run-statistics)

---

## Management Summary

### Verdict

🔴 **Critical security posture — unauthenticated attackers can achieve full system compromise through multiple independent attack chains.**

- **Authentication is fully compromised**: The RSA private key used to sign JWTs is hardcoded in source code (publicly available on GitHub), and the login endpoint has SQL injection that bypasses authentication without any credentials.
- **Remote code execution is available to authenticated users**: The B2B order endpoint executes attacker-supplied JavaScript in a bypassable VM sandbox, granting shell-level access to any user with a valid JWT.
- **The entire database is extractable without authentication**: The product search endpoint has a UNION-based SQL injection accessible to unauthenticated users, exposing all user credentials, orders, and security answers.
- **Stored XSS combined with localStorage token storage enables admin session theft**: Three Angular components disable the framework's XSS protection, and tokens are stored where JavaScript can retrieve them.

As an intentionally vulnerable training application, these findings are expected. In a production context, any one of these Critical findings would constitute a complete breach. The threat model documents each vulnerability with precise code location and a concrete remediation step.

### Top Threats

| Severity | ID | Description | Impact | Mitigation | Effort |
|----------|----|-------------|--------|------------|--------|
| 🔴 | [T-001](#t-001) | Hardcoded RSA private key → offline JWT forgery | Admin role compromise | [M-001](#m-001) — Env var for key | Medium |
| 🔴 | [T-002](#t-002) | SQL injection on login → auth bypass | Unauthenticated admin access | [M-002](#m-002) — Parameterized SQL | Low |
| 🔴 | [T-003](#t-003) | JWT alg:none → signature bypass | Full auth bypass | [M-003](#m-003) — Enforce RS256 | Medium |
| 🔴 | [T-004](#t-004) | SQL injection in search → full DB dump | All user credentials extracted | [M-002](#m-002) — Parameterized SQL | Low |
| 🔴 | [T-005](#t-005) | eval/vm RCE in B2B orders | Shell on application server | [M-005](#m-005) — Remove eval | Medium |
| 🔴 | [T-006](#t-006) | XXE in XML upload → file read | /etc/passwd, internal configs | [M-006](#m-006) — noent: false | Low |
| 🔴 | [T-007](#t-007) | Stored XSS + localStorage → admin session theft | Admin account takeover | [M-007](#m-007) — Remove bypass | Medium |
| 🟠 | [T-008](#t-008) | MD5 password hashing → credential cracking | Full credential dump cracked in minutes | [M-008](#m-008) — bcrypt | Medium |
| 🟠 | [T-009](#t-009) | NoSQL injection in reviews → data leak + DoS | Review DB exfiltration | [M-004](#m-004) — Parameterized filter | Low |
| 🟠 | [T-025](#t-025) | Path traversal in ZIP upload | Arbitrary file write outside uploads/ | [M-020](#m-020) — startsWith check | Low |

_Legend: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low_

### ⚠ Worst Case Scenarios

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

**Scenario 1 — Unauthenticated full system compromise:** An attacker downloads the public source code, extracts the hardcoded RSA private key from `lib/insecurity.ts:23`, signs an admin-role JWT offline, and uses it to access all admin APIs. Separately, they submit `admin'--` as the login email to bypass the password check entirely. Either path yields a shell via the B2B eval endpoint.

**Scenario 2 — Mass customer data exfiltration:** An unauthenticated attacker sends a UNION SELECT payload to `GET /rest/products/search?q=...` and extracts every user's email address and MD5-hashed password. Since MD5 has no salt, the passwords are cracked in minutes with a GPU. Full customer database including payment methods and order history is exfiltrated.

**Scenario 3 — Persistent admin takeover via stored XSS:** An attacker creates an account, submits a feedback comment containing a JavaScript payload that reads `localStorage.getItem('token')` and posts it to an attacker-controlled server. When an administrator views the About page, their JWT is exfiltrated. The attacker uses the token for up to 6 hours with no revocation possible.

[See Critical Attack Chain below for the visual attack flow.](#critical-attack-chain)

</blockquote>

### Architecture Assessment

The following structural design defects amplify every individual vulnerability in this application.

| Severity | Layer | Defect | Consequence | Enables |
|----------|-------|--------|-------------|---------|
| 🔴 | Authentication | No key isolation — signing key hardcoded in source | Anyone with repo access forges admin tokens offline | [T-001](#t-001) — JWT forgery, [T-003](#t-003) — alg:none |
| 🔴 | Data | SQLite in-process with raw SQL — no isolation boundary | SQL injection has full database scope with no audit trail | [T-002](#t-002) — Login SQLi, [T-004](#t-004) — Search SQLi, [T-016](#t-016) — DB scope |
| 🔴 | Code Execution | eval/vm in request handler with no safe replacement | Any authenticated user can escape sandbox to shell | [T-005](#t-005) — B2B RCE |
| 🟠 | Frontend | XSS sanitizer explicitly disabled for three components | Stored XSS persists undetected until admin page view | [T-007](#t-007) — Stored XSS, [T-018](#t-018) — IP XSS |
| 🟠 | Frontend | JWT in localStorage (not httpOnly cookie) | Any XSS becomes a session hijack | [T-015](#t-015) — Token theft |

_Legend: 🔴 Critical · 🟠 High_

### Mitigations

#### Prioritized Mitigations (P1 — Immediate)

| Priority | Mitigation | Addresses | Effort |
|----------|------------|-----------|--------|
| **P1 — Immediate** | [M-001](#m-001) — Move JWT key to env var | [T-001](#t-001) — JWT forgery, [T-003](#t-003) — alg:none | Medium |
| **P1 — Immediate** | [M-002](#m-002) — Parameterize SQL queries | [T-002](#t-002) — Login SQLi, [T-004](#t-004) — Search SQLi, [T-016](#t-016) — DB scope | Low |
| **P1 — Immediate** | [M-003](#m-003) — Enforce RS256 algorithm | [T-003](#t-003) — alg:none bypass | Medium |
| **P1 — Immediate** | [M-004](#m-004) — Parameterize NoSQL queries | [T-009](#t-009) — NoSQL injection, [T-030](#t-030) — NoSQL DoS | Low |
| **P1 — Immediate** | [M-005](#m-005) — Remove eval from B2B endpoint | [T-005](#t-005) — RCE | Medium |
| **P1 — Immediate** | [M-006](#m-006) — Disable XXE (noent: false) | [T-006](#t-006) — XXE file read | Low |
| **P1 — Immediate** | [M-007](#m-007) — Remove bypassSecurityTrustHtml | [T-007](#t-007) — Stored XSS, [T-018](#t-018) — IP XSS | Medium |
| **P1 — Immediate** | [M-008](#m-008) — Replace MD5 with bcrypt | [T-008](#t-008) — Credential cracking | Medium |

#### Follow-up Mitigations (P2/P3)

| Priority | Mitigation | Addresses | Effort |
|----------|------------|-----------|--------|
| **P2 — This Sprint** | [M-009](#m-009) — Add ownership checks | [T-010](#t-010) — Basket IDOR, [T-011](#t-011) — Export IDOR | Low |
| **P2 — This Sprint** | [M-010](#m-010) — SSRF protection | [T-012](#t-012) — SSRF | Medium |
| **P2 — This Sprint** | [M-011](#m-011) — Remove public key/FTP dirs | [T-013](#t-013) — Key exposure, [T-014](#t-014) — FTP files | Low |
| **P2 — This Sprint** | [M-012](#m-012) — JWT in httpOnly cookie | [T-015](#t-015) — Token theft | High |
| **P2 — This Sprint** | [M-014](#m-014) — Server-side role enforcement | [T-019](#t-019) — Auth bypass | Low |
| **P2 — This Sprint** | [M-020](#m-020) — Fix ZIP path traversal | [T-025](#t-025) — Path traversal | Low |
| **P3 — Next Quarter** | [M-018](#m-018) — Add CSP header | [T-023](#t-023) — No CSP | High |
| **P3 — Next Quarter** | [M-019](#m-019) — JWT revocation | [T-024](#t-024) — No revocation | High |

### Operational Strengths

| Control | What it provides | Limitation |
|---------|-----------------|------------|
| Helmet.js (noSniff + frameguard) | X-Content-Type-Options and X-Frame-Options headers prevent MIME sniffing and clickjacking | CSP and XSS filter are disabled; provides minimal XSS protection |
| express-jwt middleware | JWT signature verification on protected routes | Library is 8 major versions outdated; algorithm enforcement missing |
| CAPTCHA on feedback submission | Reduces automated spam and CAPTCHA-bypass challenge detection | Only on feedback; no challenge on login or data export |
| Rate limiting on password reset | Limits automated password reset attempts to 10/5min | Rate limiter key uses X-Forwarded-For — bypassable by header spoofing |
| CodeQL static analysis in CI | Automated detection of SQL injection, XSS, and other SAST findings | Runs on push but findings may not block merge |
| Dependabot dependency alerts | Automated detection of known vulnerable dependency versions | Response lag — express-jwt 0.1.3 and jsonwebtoken 0.4.0 remain in use |
| Morgan HTTP access logging | Captures all HTTP request/response metadata | No security events (login failures, privilege escalation) logged |
| sanitize-filename for uploads | Prevents null byte and traversal sequences in uploaded filenames | Content type not validated beyond extension; no magic byte check |

**Bottom line:** The application has structural security controls (authentication middleware, rate limiting, logging) but each is undermined by implementation defects. The authentication stack is the most critical gap — three independent bypass methods exist simultaneously.

---

## Critical Attack Chain

The diagrams below show how Critical findings combine into two distinct attacker workflows. Nodes link to their full detail row in Section 8.1.

### Chain 1 — Unauthenticated Admin Takeover

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated<br/>attacker"]):::crit
    T1["[T-001](#t-001)<br/>Hardcoded RSA key"]:::crit
    T3["[T-003](#t-003)<br/>JWT alg:none"]:::crit
    T5["[T-005](#t-005)<br/>B2B eval RCE"]:::crit
    Goal(["Shell on server"]):::crit
    Start -->|"public GitHub repo"| T1
    T1 -->|"sign admin JWT offline"| T5
    T3 -->|"forge unsigned JWT"| T5
    T5 -->|"vm escape via prototype pollution"| Goal
```

**Key takeaway:** An unauthenticated attacker needs only to clone the public repository to obtain the signing key — three independent authentication bypasses then chain to a remote code execution in under a minute.

### Chain 2 — Mass Customer Data Exfiltration

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated<br/>attacker"]):::crit
    T2["[T-002](#t-002)<br/>Login SQLi"]:::crit
    T4["[T-004](#t-004)<br/>Search UNION SQLi"]:::crit
    T8["[T-008](#t-008)<br/>MD5 cracking"]:::crit
    Goal(["Full customer DB<br/>+ cracked passwords"]):::crit
    Start -->|"email: admin'--"| T2
    Start -->|"q=') UNION SELECT..."| T4
    T4 -->|"dump MD5 hashes"| T8
    T8 -->|"10B hashes/sec GPU"| Goal
```

**Key takeaway:** Two separate unauthenticated SQL injection endpoints give full database access — the MD5 password storage means cracked credentials follow within minutes of extraction.

### Chain 3 — Persistent Stored XSS to Admin Session Theft

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Registered user<br/>(any account)"]):::crit
    T7["[T-007](#t-007)<br/>Stored XSS<br/>bypassSecurityTrustHtml"]:::crit
    T15["[T-015](#t-015)<br/>JWT in<br/>localStorage"]:::crit
    Goal(["Admin session<br/>for 6 hours"]):::crit
    Start -->|"POST feedback with JS payload"| T7
    T7 -->|"admin views About page"| T15
    T15 -->|"localStorage.getItem token"| Goal
```

**Key takeaway:** A low-privilege registered user can persistently compromise the admin session by storing a JavaScript payload in feedback — Angular's XSS protection is explicitly disabled in the components that render it.

### Quick Reference — Critical Findings

| ID | Title | Component | Mitigation |
|----|-------|-----------|------------|
| [T-001](#t-001) | Hardcoded RSA Private Key | Authentication Service | [M-001](#m-001) — Move key to env var |
| [T-002](#t-002) | Login SQL Injection | Authentication Service | [M-002](#m-002) — Parameterized SQL |
| [T-003](#t-003) | JWT Algorithm Confusion | Authentication Service | [M-003](#m-003) — Enforce RS256 |
| [T-004](#t-004) | Search SQL Injection | REST API | [M-002](#m-002) — Parameterized SQL |
| [T-005](#t-005) | B2B eval/vm RCE | REST API | [M-005](#m-005) — Remove eval |
| [T-006](#t-006) | XXE File Read | File Upload Processor | [M-006](#m-006) — noent: false |
| [T-007](#t-007) | Stored XSS Admin Session Theft | Angular SPA | [M-007](#m-007) — Remove bypass |

---

## 1. System Overview

OWASP Juice Shop is an intentionally insecure web application created by the OWASP Foundation for security training, awareness, and CTF (Capture the Flag) competitions. It is a full-stack Node.js/Angular application hosting hundreds of security challenges across all OWASP Top 10 categories and beyond. Version 19.2.1 is the assessed version.

**Deployment:** The application runs as a Docker container exposing port 3000. It uses an in-process SQLite database (via Sequelize ORM) for users, products, and orders, and a marsdb (MongoDB-compatible in-process store) for reviews and complaint orders. In the default deployment there is no API gateway, no WAF, no reverse proxy, and no TLS termination — the Express server handles all traffic directly.

**Users:** Developers learning about web security vulnerabilities, security professionals conducting awareness training, and CTF participants solving challenges. In a real-world context, this is a public-facing e-commerce platform handling customer PII, payment data, and session tokens.

**Complexity tier:** Moderate — Express monolith backend with Angular SPA frontend, two in-process databases, and approximately 50 route handlers. A Container-level architecture diagram is included in addition to the System Context view.

**Context sources:** Cached business context file from previous run. No external context endpoint configured. No requirements YAML.

**Security impression:** This application has the worst possible security posture by design — it is an intentional training target. Every finding documented in this threat model would constitute a critical breach in production. The analysis is valuable because it documents real vulnerability patterns that occur in production applications. From an architecture perspective, the primary structural weakness is the complete absence of key isolation, the in-process database model, and the explicit disabling of standard security controls (XSS filter commented out, algorithm enforcement absent).

---

## 2. Architecture Diagrams

The following diagrams model the system architecture at different abstraction levels using the C4 model. Security-relevant components with Medium-or-higher threats are highlighted in red (using the `:::risk` class).

### 2.1 System Context

The Context view shows who interacts with the system, which external services it depends on, and which trust zones each actor sits in. All inbound traffic reaches the Express monolith directly — there is no API gateway or WAF in the default deployment.

```mermaid
graph TD
    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["Public Internet — untrusted"]
        User["End User / CTF Player\nBrowser-based"]:::person
        Attacker["Attacker\nUnauthenticated or registered"]:::person
    end

    subgraph APP["Application Host — trusted"]
        %% component: rest-api
        JuiceShop["OWASP Juice Shop v19.2.1\nExpress 4 Monolith\nNode.js 20 · Docker"]:::risk
        %% component: frontend-spa
        Angular["Angular SPA\nAngular 19\nBuilt static assets"]:::risk
    end

    subgraph DATA["Data Tier — in-process"]
        %% component: data-access
        SQLite["SQLite DB\nvia Sequelize\nUsers, Products, Orders"]:::risk
        marsdb["marsdb\nMongoDB-compatible\nReviews, Complaints"]:::risk
    end

    User -->|"HTTP/HTTPS port 3000"| JuiceShop
    Attacker -->|"HTTP/HTTPS port 3000"| JuiceShop
    JuiceShop -->|"serves static SPA assets"| Angular
    JuiceShop -->|"SQL via Sequelize in-process"| SQLite
    JuiceShop -->|"JS collection API in-process"| marsdb

    %% Trust Boundary Key:
    %% INTERNET → APP: No WAF, no API gateway — direct TCP to Express port 3000
    %% APP → DATA: In-process — no network isolation; SQL injection has full DB scope
```

**Key takeaway:** Every external request — including an unauthenticated attacker — reaches the Express monolith directly on port 3000 with no gateway, no WAF, and no TLS termination in the default deployment.

### 2.2 Container Architecture

The Container view zooms into the deployable units. The critical observation: both databases run in the same process as the application, meaning any code injection vulnerability has direct memory access to all data.

```mermaid
graph TD
    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    Browser["Browser\nAngular SPA 19\nLocalStorage JWT"]:::risk

    subgraph Docker["Docker Container — port 3000"]
        subgraph Express["Express Monolith"]
            %% component: auth-service
            Auth["Authentication Service\nlib/insecurity.ts\nHardcoded RSA key"]:::risk
            %% component: rest-api
            API["REST API Routes\n~50 route handlers\nserver.ts"]:::risk
            %% component: file-processor
            Files["File Processor\nroutes/fileUpload.ts\nXXE / Path traversal"]:::risk
            B2B["B2B Order Endpoint\nroutes/b2bOrder.ts\neval/vm RCE"]:::risk
        end

        subgraph InProcess["In-Process Databases"]
            %% component: data-access
            SQLite["SQLite\nvia Sequelize\nusers, products, orders"]:::risk
            marsdb["marsdb\nreviews, complaints"]:::risk
        end
    end

    FTP["ftp/ directory\nPublic sensitive files\nKeePass, backups"]:::risk
    Keys["encryptionkeys/\nPublic JWT key\nPublicly served"]:::risk

    Browser -->|"HTTP REST · port 3000"| API
    API -->|"SQL · in-process"| SQLite
    API -->|"JS collection · in-process"| marsdb
    API -->|"delegates to"| Auth
    API -->|"delegates to"| Files
    API -->|"delegates to"| B2B
    API -->|"serves at /ftp"| FTP
    API -->|"serves at /encryptionkeys"| Keys

    %% Trust Boundary Key:
    %% Browser → Docker: HTTP on port 3000, no TLS enforced by default
    %% Express → SQLite/marsdb: In-process call — no network isolation
    %% Public → /ftp, /encryptionkeys: No authentication required
```

**Key takeaway:** The in-process database model means SQL and NoSQL injection vulnerabilities have full database scope with no network-level isolation — there is no separate database process to limit blast radius.

### 2.3 Technology Architecture

This diagram shows the runtime middleware stack from top to bottom. Nodes in red carry at least one High-or-Critical threat.

```mermaid
graph TD
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph BROWSER["Browser Layer"]
        AngularSPA["Angular 19 SPA\nionic UI components\nLocalStorage token storage"]:::risk
        Interceptor["HTTP Interceptor\nBearer token from localStorage\nX-User-Email header"]:::risk
    end

    subgraph SERVER["Server Layer — Express 4.22"]
        Helmet["Helmet 4.x\nnoSniff + frameguard only\nNo CSP · No XSS filter"]:::risk
        CORSMw["CORS Middleware\nWildcard — all origins allowed"]:::risk
        JWT["express-jwt 0.1.3\nRS256 isAuthorized()\njws.verify — alg:none accepted"]:::risk
        Routes["Route Handlers\n~50 TypeScript modules\nRaw SQL interpolation"]:::risk
        BodyParser["body-parser\nurlencode + JSON + text"]
        Morgan["Morgan Logger\nHTTP combined format\nNo security audit log"]:::risk
    end

    subgraph DATA_LAYER["Data Layer — In-Process"]
        Sequelize["Sequelize 6.37\nSQLite dialect\nRaw query allowed"]:::risk
        Marsdb["marsdb 0.6.11\nMongoDB-compat\n$where injection"]:::risk
        SQLiteFile["SQLite database file\njuice-shop.sqlite"]:::risk
    end

    AngularSPA -->|"HTTP REST"| JWT
    Interceptor -->|"injects Authorization header"| Routes
    Helmet --> CORSMw
    CORSMw --> JWT
    JWT --> Routes
    Routes --> BodyParser
    BodyParser --> Morgan
    Routes -->|"Sequelize.query raw SQL"| Sequelize
    Routes -->|"collection.find dollar-where"| Marsdb
    Sequelize -->|"SQLite file I/O"| SQLiteFile
```

**Key takeaway:** The middleware chain has no rate limiting on most endpoints, no CSP, a wildcard CORS policy, and an authentication library that is 8 major versions behind — each layer weakens the security posture of the one above it.

### 2.4 Security Architecture Assessment

The assessment below evaluates structural patterns rather than individual code defects. Each pattern is rated based on code and configuration evidence from the reconnaissance phase.

#### 2.4.1 Architecture Patterns

The following table evaluates which security architecture patterns are implemented. Each pattern is rated as present, partially implemented, or absent based on direct code evidence.

| Pattern | Status | Assessment |
|---------|--------|------------|
| API Gateway | ❌ Absent | No centralized gateway in front of Express. Authentication, rate limiting, and request validation must be implemented per-route, leading to inconsistent enforcement — several routes lack auth middleware entirely. |
| BFF (Backend for Frontend) | ❌ Absent | Angular SPA communicates directly with the Express REST API. The BFF pattern would isolate the browser's attack surface; without it, any XSS can call any backend endpoint with the stolen JWT. |
| Defense-in-Depth | ❌ Absent | Multiple identical vulnerabilities exist at the same layer (three independent authentication bypasses, two SQL injection endpoints). Depth requires different controls at each layer; here the same pattern fails repeatedly. |
| Separation of Concerns | ⚠️ Partial | Auth logic is centralized in `lib/insecurity.ts` but includes hardcoded keys, weakening the trust boundary. Route handlers mix business logic with raw SQL construction. |
| Least Privilege | ❌ Absent | SQLite runs in-process with no user-level privilege separation. The B2B eval endpoint executes with full application process privileges. Admin APIs accessible to any authenticated user. |
| Secrets Management | ❌ Absent | Three secrets hardcoded in source code: RSA private key (lib/insecurity.ts:23), HMAC key (lib/insecurity.ts:44), and cookie secret (server.ts:289). No vault or env var usage for these. |
| Network Segmentation | ❌ Absent | No network separation between web tier and data tier — both run in the same process. No firewall rules, no container network policies, no internal network for database access. |
| Secure Defaults | ⚠️ Partial | Helmet provides baseline headers; some routes have rate limiting. However, CORS is wildcard, XSS filter is commented out, and the authentication library is severely outdated. |

**Assessment:** Only 2 of 8 fundamental security architecture patterns are partially present; 6 are entirely absent. The structural consequence is that individual code fixes do not reduce systemic risk — the same class of attack succeeds through different vectors because no architectural layer provides a safety net.

#### 2.4.2 Key Architectural Risks

The following table identifies structural design decisions that amplify or enable individual vulnerabilities. These are not code-level bugs but architecture-level defects — fixing individual threats without addressing the underlying structural risk leaves the system exposed to the same class of attack through different vectors.

| Risk | Structural Risk | Why this matters | Linked Threats |
|------|----------------|-----------------|----------------|
| 🔴 Critical | **No key isolation** — The RSA private key that signs all authentication tokens is co-located with application business logic in a public repository. | A correctly designed architecture stores signing keys outside the code repository in a vault or HSM. Here, any code read access (including git clone) yields the ability to forge authentication tokens indefinitely — there is no rotation, no key versioning, and no revocation. | [T-001](#t-001) — JWT forgery<br/>[T-003](#t-003) — alg:none |
| 🔴 Critical | **In-process database with no isolation** — SQLite and marsdb run in the same process as the web server, connected via ORM and direct collection access. | A correct architecture places the database in a separate process with a dedicated service account having only the permissions needed for the application. Here, SQL injection in any route handler has unrestricted access to the entire schema with no audit trail at the database layer. | [T-002](#t-002) — Login SQLi<br/>[T-004](#t-004) — Search SQLi<br/>[T-016](#t-016) — DB scope |
| 🔴 Critical | **Eval in request handler** — The B2B order endpoint executes user-supplied JavaScript expressions inside a Node.js VM context with no safe alternative code path. | A correct architecture validates structured input against a schema. Executing user-supplied code in any form creates an irreducible RCE surface — no sandbox is sufficient because sandbox escapes are regularly discovered in all VM implementations. | [T-005](#t-005) — B2B RCE |
| 🟠 High | **XSS protection explicitly disabled** — Three Angular components call `bypassSecurityTrustHtml()`, deliberately disabling the framework's built-in output encoding for user-controlled content. | Angular's sanitizer was specifically designed to prevent this class of attack. Bypassing it transforms stored XSS from a framework-prevented vulnerability into a guaranteed exploit path for any stored HTML. | [T-007](#t-007) — Stored XSS<br/>[T-018](#t-018) — IP XSS |
| 🟠 High | **Token in untrusted storage** — JWTs are stored in localStorage, which is accessible to any JavaScript executing on the page. | A correct architecture stores session tokens in httpOnly cookies, which are inaccessible to JavaScript. The combination of XSS vulnerabilities and localStorage storage means any XSS is automatically a session hijack. | [T-015](#t-015) — Token theft |

#### 2.4.3 Secret Management

**Current state.** Three application secrets are hardcoded directly in source code: the RSA private key for JWT signing at [`lib/insecurity.ts:23`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23), the HMAC signing key at [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44), and the Express cookie signing secret at [`server.ts:289`](vscode://file/home/mrohr/juice-shop/server.ts:289). No secrets manager, vault, or environment variable loading is used for any of these.

**Structural defects:**

- RSA private key (1024-bit) hardcoded at [`lib/insecurity.ts:23-25`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) — enables offline JWT forgery from public repo
- HMAC secret `'pa4qacea4VK9t9nGv7yZtwmj'` hardcoded at [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44) — enables coupon forgery and security answer brute-force
- Cookie secret `'kekse'` hardcoded at [`server.ts:289`](vscode://file/home/mrohr/juice-shop/server.ts:289) — enables signed cookie forgery
- No secret rotation capability — rotating any key requires a code change and redeployment
- No audit trail for secret access — compromise is undetectable

**Impact.** An attacker with read access to the source code (public GitHub repository) has permanent ability to forge authentication tokens, generate discount coupons, and brute-force account passwords — all without any network interaction.

**Target architecture.** Load all secrets from `process.env.*` at startup, fail immediately if required variables are absent, and provision them in production via HashiCorp Vault or cloud-native secrets management (AWS Secrets Manager, GCP Secret Manager). Rotate the JWT key pair on a 90-day schedule.

**Linked threats:**

- [T-001](#t-001) — JWT forgery via hardcoded RSA key
- [T-028](#t-028) — Coupon forgery via hardcoded HMAC key
- [T-029](#t-029) — Cookie forgery via hardcoded cookie secret

#### 2.4.4 Authentication

**Current state.** RS256 JWT issued on login at [`routes/login.ts:44`](vscode://file/home/mrohr/juice-shop/routes/login.ts:44); [`lib/insecurity.ts:56`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:56) signs tokens with the hardcoded private key; [`lib/insecurity.ts:57`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) verifies without algorithm enforcement using jws.verify; express-jwt 0.1.3 accepts alg:none.

**Structural defects:**

- Signing key co-located with signing and verification code at [`lib/insecurity.ts:23`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) — no key isolation
- Algorithm enforcement absent on `jws.verify()` — attacker switches to alg:none ([`lib/insecurity.ts:57`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57))
- Private key hardcoded in source code — anyone with GitHub access forges tokens offline
- Login route has SQL injection at [`routes/login.ts:44`](vscode://file/home/mrohr/juice-shop/routes/login.ts:44) — authentication bypassed without a token at all
- Token stored in localStorage ([`frontend/src/app/Services/request.interceptor.ts:13`](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13)) — XSS extractable
- No token revocation — compromised tokens valid for 6 hours after theft
- express-jwt 0.1.3 is approximately 8 major versions behind current (8.x)

**Impact.** An attacker has three independent paths to a valid admin JWT: (1) extract the hardcoded key and sign offline, (2) submit a JWT with alg:none, (3) bypass password check via SQL injection. Any XSS then steals that token from localStorage for persistent access.

**Target architecture.** Delegate authentication to an external OIDC identity provider; the application verifies signatures via the IdP's published JWKS endpoint and enforces RS256. Tokens stored in httpOnly cookies. Short-lived access tokens (15 min) with refresh token rotation.

```mermaid
graph TD
    subgraph CLIENT["Browser"]
        LOGIN_FORM["Login Form\nPOST /rest/user/login"]
        LS["localStorage\nJWT token (vulnerable)"]:::risk
    end
    subgraph SERVER["Express Monolith"]
        LOGIN_ROUTE["routes/login.ts:44\nRaw SQL — SQLi possible"]:::risk
        INSECURITY["lib/insecurity.ts:23\nsign() · RSA key HARDCODED"]:::risk
        VERIFY["lib/insecurity.ts:57\njws.verify() · alg:none accepted"]:::risk
        PROTECTED["Protected Routes\nisAuthorized() middleware"]
    end
    LOGIN_FORM -->|"POST email password"| LOGIN_ROUTE
    LOGIN_ROUTE -->|"if SQL returns row — sign JWT"| INSECURITY
    INSECURITY -->|"JWT in response body"| LS
    LS -->|"Authorization: Bearer"| VERIFY
    VERIFY -->|"decoded user object"| PROTECTED
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** The authentication chain has three independent critical breaks — SQL injection bypasses credential check, alg:none bypasses signature verification, and the hardcoded private key enables offline forgery — any single break yields admin access without needing the others.

**Linked threats:**

- [T-001](#t-001) — Hardcoded RSA key enables offline forgery
- [T-002](#t-002) — SQL injection bypasses login
- [T-003](#t-003) — alg:none bypasses verification
- [T-008](#t-008) — MD5 hashing enables credential cracking
- [T-024](#t-024) — No token revocation

#### 2.4.5 Authorization & Access Control

**Current state.** Role-based access control uses four roles (customer, deluxe, accounting, admin) defined in [`models/user.ts:87`](vscode://file/home/mrohr/juice-shop/models/user.ts:87). `isAuthorized()` middleware at [`lib/insecurity.ts:54`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) verifies JWT signature but does not check role. `isAccounting()` and `isDeluxe()` role checks exist at [`lib/insecurity.ts:157-175`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:157-175) but are not applied to admin endpoints.

**Structural defects:**

- Admin API endpoints (`/rest/admin/*`) only require `isAuthorized()` — no role check ([`server.ts:604-605`](vscode://file/home/mrohr/juice-shop/server.ts:604))
- `GET /api/Users` returns all user records to any authenticated user ([`server.ts:362`](vscode://file/home/mrohr/juice-shop/server.ts:362))
- Angular frontend guards are client-side only — bypassed by direct API calls
- IDOR on basket retrieval — no ownership check ([`routes/basket.ts:19`](vscode://file/home/mrohr/juice-shop/routes/basket.ts:19))
- IDOR on data export — UserId taken from request body ([`routes/dataExport.ts:26`](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26))

**Impact.** Any authenticated user (customer role) can access admin configuration, the full user list, and any other user's basket contents by directly calling the APIs.

**Target architecture.** Apply `isAdmin()` middleware to all `/rest/admin/*` routes. Derive resource ownership from the authenticated JWT payload, never from request body parameters. Remove reliance on client-side Angular guards for security decisions.

**Linked threats:**

- [T-010](#t-010) — Basket IDOR
- [T-011](#t-011) — Data export IDOR
- [T-019](#t-019) — Admin API accessible to any authenticated user

#### 2.4.6 Input Validation & Output Encoding

**Current state.** Input validation is inconsistent — some routes apply `sanitize-html` or `sanitize-filename`, while the most sensitive endpoints (login, search, B2B order) use raw string interpolation in database queries. Output encoding in Angular is explicitly bypassed for three components via `bypassSecurityTrustHtml`.

**Structural defects:**

- Raw SQL string interpolation at login and search routes — parameterization not used
- `$where` string concatenation in MongoDB queries — parameterized filter not used
- `bypassSecurityTrustHtml` disabled in three Angular components — output encoding bypassed
- `safeEval` called with user-supplied input — code execution rather than data parsing
- File type validated by extension only — no magic byte verification

**Impact.** Multiple classes of injection are simultaneously exploitable: SQL injection to database, NoSQL injection to MongoDB store, XSS to browser DOM, and code injection to Node.js runtime.

**Target architecture.** Parameterize all database queries at the ORM level. Enforce Angular's default output encoding — never call `bypassSecurityTrustHtml`. Replace eval-based code with structured JSON schema validation. Validate uploaded file content against magic bytes, not extensions.

**Linked threats:**

- [T-002](#t-002) — Login SQLi
- [T-004](#t-004) — Search SQLi
- [T-007](#t-007) — Stored XSS
- [T-009](#t-009) — NoSQL injection

#### 2.4.7 Separation & Isolation

**Current state.** The application is a monolith where all route handlers share the same process, the same in-memory database connections, and the same filesystem access. There are no container network policies, no process-level separation between API components, and no privilege separation between the web application layer and the data tier.

**Structural defects:**

- SQLite and marsdb run in-process — DB compromise is automatic on application RCE
- B2B eval endpoint executes with full process privileges — no sandbox isolation
- File upload processor writes to disk with the same permissions as the web server
- FTP and encryption key directories served from the same process — same privilege boundary

**Impact.** A single RCE exploit ([T-005](#t-005)) gives the attacker full control of all data, all secrets, all filesystem paths accessible to the application user — there is no secondary containment.

**Target architecture.** Run the application as a non-root user with minimal filesystem permissions. Move databases to separate processes with dedicated service accounts. Consider process-level isolation for the file upload handler and rate-limit inbound connections at the network layer.

**Linked threats:**

- [T-005](#t-005) — RCE with full process privileges
- [T-013](#t-013) — Encryption keys publicly accessible
- [T-014](#t-014) — FTP directory publicly accessible

#### 2.4.8 Defense-in-Depth

**Current state.** See the Technology Architecture diagram (Section 2.3) for the runtime middleware stack. The Express middleware chain has: Helmet (noSniff + frameguard only), wildcard CORS, no CSP, express-jwt for protected routes, Morgan for HTTP logging, and per-route rate limiting on only two endpoints. There is no WAF, no API gateway, no anomaly detection, and no network-level rate limiting.

**Structural defects:**

- No WAF or API gateway in front of Express — all attack traffic reaches application code
- No CSP header — browser cannot restrict XSS script execution
- CORS wildcard — any origin can make authenticated cross-origin requests
- Rate limiting on password reset only — no protection on login, search, or file upload
- No security event logging — failed auth attempts, privilege escalations, data exports not recorded
- Helmet XSS filter explicitly commented out at [`server.ts:187`](vscode://file/home/mrohr/juice-shop/server.ts:187)

**Impact.** There is no layer that would slow or detect an attack — every vulnerability is immediately exploitable from the public internet with no friction.

**Target architecture.** Add a WAF or API gateway in front of Express. Enable CSP with strict-dynamic. Restrict CORS to known origins. Add rate limiting to all mutation endpoints. Implement security event logging to a separate, tamper-evident stream.

**Linked threats:**

- [T-022](#t-022) — CORS wildcard
- [T-023](#t-023) — No CSP
- [T-017](#t-017) — Unauthenticated metrics
- [T-027](#t-027) — No audit logging

#### 2.4.9 Overall Architecture Security Rating

🔴 **Critical gaps** — The application has critical structural defects in every evaluated security dimension: secrets are hardcoded in the public repository, the database runs in-process with no isolation, user-supplied code is executed in a bypassable sandbox, the XSS protection framework is explicitly disabled, and authentication tokens are stored where JavaScript can read them. Six of eight fundamental security architecture patterns are entirely absent. These are not implementation bugs that can be fixed with targeted patches — they are architectural decisions that require structural change to the way secrets are managed, code is executed, and trust boundaries are enforced.

---

## 3. Attack Walkthroughs

The sequence diagrams below trace three Critical findings from initial attacker action to full exploitation. Each diagram shows the current vulnerable behavior in the `alt` branch and the post-mitigation behavior in the `else` branch.

### SQL Injection Login Bypass ([T-002](#t-002))

This sequence shows how a single crafted email parameter bypasses authentication entirely and yields an admin session via SQL injection on the login endpoint.

```mermaid
sequenceDiagram
    actor Attacker
    participant Browser
    participant LoginRoute as routes/login.ts
    participant DB as SQLite (in-process)

    Attacker->>Browser: Navigate to /#/login
    Browser->>LoginRoute: POST /rest/user/login {email: "admin'--", password: "anything"}

    alt Current state — T-002 SQL Injection
        LoginRoute->>DB: SELECT * FROM Users WHERE email = 'admin'--' AND password = '...' AND deletedAt IS NULL
        Note over DB: Password check commented out by -- injection
        DB-->>LoginRoute: Returns admin user row
        LoginRoute-->>Browser: 200 {token: admin_jwt, bid: 1}
        Browser-->>Attacker: Admin JWT stored in localStorage
        Note over Attacker: Full admin access — no password needed
    else After M-002 — Parameterized SQL
        LoginRoute->>DB: SELECT * FROM Users WHERE email = :email AND password = :password
        Note over DB: Apostrophe treated as literal data, not SQL syntax
        DB-->>LoginRoute: Returns no rows
        LoginRoute-->>Browser: 401 Invalid email or password
    end
```

**Key takeaway:** The SQL injection does not require any special tools — a simple string in the email field breaks the WHERE clause and grants admin access without knowing the password.

### Hardcoded Key JWT Forgery ([T-001](#t-001))

This sequence shows how the hardcoded RSA private key enables offline JWT forgery to any role without any network interaction.

```mermaid
sequenceDiagram
    actor Attacker
    participant GitHub as Public GitHub Repo
    participant Offline as Attacker Machine (offline)
    participant API as REST API

    Attacker->>GitHub: git clone https://github.com/juice-shop/juice-shop
    GitHub-->>Attacker: Full source code including lib/insecurity.ts
    Attacker->>Offline: Extract private key from lib/insecurity.ts:23-25
    Attacker->>Offline: jwt.sign({data:{id:1,role:'admin',email:'admin@juice-sh.op'}}, privateKey, {algorithm:'RS256'})
    Offline-->>Attacker: Forged admin JWT (no network request to target)

    alt Current state — T-001 Hardcoded Key
        Attacker->>API: GET /rest/admin/application-configuration with forged JWT
        API-->>Attacker: 200 Full application configuration
        Attacker->>API: POST /b2b/v2/orders with forged JWT and eval payload
        API-->>Attacker: RCE — shell on application server
    else After M-001 — Key from Environment Variable
        Note over Offline: Private key not in source code
        Note over API: New key unknown to attacker — forged JWT fails verification
        API-->>Attacker: 401 Unauthorized
    end
```

**Key takeaway:** The attacker never needs to interact with the live application to obtain admin credentials — the signing key is in the public repository and the token is forged entirely offline.

### Stored XSS Admin Session Theft ([T-007](#t-007))

This sequence shows how a registered user stores a persistent XSS payload that captures the administrator's JWT from localStorage when the About page is viewed.

```mermaid
sequenceDiagram
    actor RegUser as Registered User (attacker)
    actor Admin
    participant FeedbackAPI as POST /api/Feedbacks
    participant DB as MongoDB (marsdb)
    participant AboutPage as Angular About Component
    participant LocalStorage as localStorage

    RegUser->>FeedbackAPI: POST /api/Feedbacks {comment: "script payload exfiltrating token"}
    FeedbackAPI->>DB: Insert feedback with unsanitized comment

    alt Current state — T-007 Stored XSS
        Admin->>AboutPage: Navigate to /#/about
        AboutPage->>FeedbackAPI: GET /api/Feedbacks
        FeedbackAPI-->>AboutPage: Returns feedbacks including malicious comment
        AboutPage->>LocalStorage: bypassSecurityTrustHtml renders script
        LocalStorage-->>RegUser: localStorage.getItem('token') exfiltrated
        Note over RegUser: Admin JWT valid for 6 hours — full admin access
    else After M-007 — Remove bypassSecurityTrustHtml
        Admin->>AboutPage: Navigate to /#/about
        AboutPage->>FeedbackAPI: GET /api/Feedbacks
        FeedbackAPI-->>AboutPage: Returns feedbacks
        Note over AboutPage: Angular text binding — script tags rendered as text
        AboutPage-->>Admin: Feedback displayed as plain text — no script execution
    end
```

**Key takeaway:** The stored XSS payload is persistent — it executes for every admin who views the About page until it is manually removed from the database, and each execution yields a 6-hour admin session with no revocation possible.

---

## 4. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them.

**Classification legend:** Restricted — highest sensitivity, regulatory/legal impact if exposed · Confidential — significant business impact if disclosed · Internal — limited external value but useful for reconnaissance · Public — intended for public consumption

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| User Credentials (email + MD5 hash) | Restricted | Stored in SQLite Users table; unsalted MD5 allows rapid cracking | [T-002](#t-002), [T-004](#t-004), [T-008](#t-008) |
| JWT RSA Private Signing Key | Restricted | 1024-bit RSA key hardcoded in lib/insecurity.ts — enables offline token forgery | [T-001](#t-001), [T-003](#t-003) |
| JWT Bearer Tokens | Confidential | Stored in localStorage; 6-hour lifetime; no revocation mechanism | [T-015](#t-015), [T-024](#t-024) |
| Customer PII | Confidential | Email, address, payment reference, order history in SQLite and marsdb | [T-004](#t-004), [T-010](#t-010), [T-011](#t-011) |
| Payment Method Information | Restricted | Credit/debit card data in Cards table via Sequelize | [T-004](#t-004), [T-010](#t-010) |
| Wallet Balances | Confidential | Cryptocurrency wallet balances | [T-004](#t-004) |
| Security Questions and HMAC Answers | Restricted | Used for password reset; HMAC key hardcoded in source | [T-020](#t-020), [T-028](#t-028) |
| Encryption Keys Directory | Restricted | JWT public key and premium.key served publicly at /encryptionkeys/ | [T-013](#t-013) |
| FTP Directory Contents | Confidential | KeePass DB, coupon codes, dependency backup files — publicly accessible | [T-014](#t-014) |
| HMAC Secret Key | Restricted | 'pa4qacea4VK9t9nGv7yZtwmj' hardcoded — enables coupon forgery | [T-028](#t-028) |
| Product Catalog | Internal | Products, pricing, descriptions in SQLite | [T-004](#t-004) |
| Application Configuration | Internal | /rest/admin/application-configuration — accessible to any authenticated user | [T-019](#t-019) |
| Access and Application Logs | Internal | Morgan HTTP logs only; no security audit trail | [T-027](#t-027) |
| Challenge State | Internal | CTF challenge tracking — not security-sensitive in itself | — |


---

## 5. Attack Surface

All identified entry points through which an attacker can interact with the system, split by whether authentication is required. Unauthenticated entry points represent the highest-priority attack surface.

### 5.1 Unauthenticated Entry Points (8)

These endpoints are accessible without any authentication. They represent the outermost attack surface and include the most severe vulnerabilities in the application.

| ID | Entry Point | Protocol | Notes | Linked Threats |
|----|-------------|----------|-------|----------------|
| E-001 | POST /rest/user/login | HTTP/REST | SQL injection via email/password fields | [T-002](#t-002) |
| E-002 | GET /rest/products/search | HTTP/REST | SQL injection via ?q= parameter; UNION SELECT DB dump | [T-004](#t-004) |
| E-003 | POST /file-upload | HTTP/Multipart | XXE via XML; path traversal in ZIP; YAML deserialization | [T-006](#t-006), [T-025](#t-025) |
| E-004 | GET /ftp | HTTP | Public directory listing with KeePass DB, coupon codes, backup manifests | [T-014](#t-014) |
| E-005 | GET /encryptionkeys | HTTP | Public key directory listing — JWT public key, premium.key | [T-013](#t-013) |
| E-006 | GET /metrics | HTTP | Unauthenticated Prometheus metrics — internal application state | [T-017](#t-017) |
| E-007 | GET /api-docs | HTTP | Swagger UI with full API documentation — aids enumeration | — |
| E-008 | POST /rest/user/reset-password | HTTP/REST | Security question reset; bypassable rate limit via X-Forwarded-For | [T-020](#t-020) |

### 5.2 Authenticated Entry Points (14)

These endpoints require a valid JWT. However, authentication is bypassable via multiple paths ([T-001](#t-001), [T-002](#t-002), [T-003](#t-003)), so these endpoints are effectively accessible to unauthenticated attackers in practice.

| Entry Point | Protocol | Auth Level | Notes | Linked Threats |
|-------------|----------|-----------|-------|----------------|
| GET /rest/basket/:id | HTTP/REST | Any valid JWT | IDOR — no ownership check | [T-010](#t-010) |
| POST /rest/user/data-export | HTTP/REST | Any valid JWT | IDOR — UserId from request body | [T-011](#t-011) |
| POST /profile/image/url | HTTP/REST | Any valid JWT | SSRF — arbitrary URL fetched server-side | [T-012](#t-012) |
| POST /b2b/v2/orders | HTTP/REST | Any valid JWT | RCE via eval/vm sandbox escape | [T-005](#t-005) |
| GET /rest/products/:id/reviews | HTTP/REST | None (unauthenticated) | NoSQL injection via $where | [T-009](#t-009) |
| GET /rest/admin/application-version | HTTP/REST | Any valid JWT | Admin endpoint — no role check | [T-019](#t-019) |
| GET /rest/admin/application-configuration | HTTP/REST | Any valid JWT | Admin endpoint — no role check | [T-019](#t-019) |
| GET /api/Users | HTTP/REST | Any valid JWT | Full user list — no admin role check | [T-019](#t-019) |
| GET /redirect | HTTP | None | Open redirect — allowlist bypassable | [T-021](#t-021) |
| GET /rest/user/authentication-details | HTTP/REST | Any valid JWT | Returns all active sessions | — |
| POST /api/Users | HTTP/REST | None | User registration — role field injectable | — |
| POST /rest/user/change-password | HTTP/REST | Partial | Password change without current password in some flows | — |
| POST /profile/image/file | HTTP/Multipart | Any valid JWT | Profile image upload | [T-026](#t-026) |
| POST /chatbot | HTTP/REST | Any valid JWT | Chatbot interaction | — |

---

## 6. Trust Boundaries

Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk. The overall trust model is severely weakened by the absence of an API gateway and the in-process database architecture — an attacker who breaches the Express layer immediately has access to all data.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|--------------|----------------|
| 1 | Internet to Express Monolith | Public Internet (untrusted) | Express application (port 3000) | None — no WAF, no API gateway, no TLS enforcement in default deployment | All unauthenticated attack traffic reaches application code without friction | [T-002](#t-002), [T-004](#t-004), [T-006](#t-006) |
| 2 | Express to SQLite (in-process) | Express route handlers | SQLite database | Sequelize ORM (but raw queries bypassed) | In-process — SQL injection in any route has full database scope with no audit trail | [T-002](#t-002), [T-004](#t-004), [T-016](#t-016) |
| 3 | Express to marsdb (in-process) | Express route handlers | marsdb collection | Collection API | In-process — NoSQL injection in review routes has full collection scope | [T-009](#t-009), [T-030](#t-030) |
| 4 | Browser to Angular SPA | User browser (untrusted) | Angular application | Angular framework sanitization | Three components explicitly bypass Angular's XSS protection; JWT in localStorage | [T-007](#t-007), [T-015](#t-015), [T-018](#t-018) |

**Boundary 1 (Internet to Express):** The most critical missing control is a WAF or API gateway in front of the Express server. All SQL injection, XXE, RCE, and SSRF attacks arrive at application code without any network-level challenge or inspection. Rate limiting is applied only to two endpoints.

**Boundary 2 (Express to SQLite):** The in-process database model eliminates the possibility of database-level access control. Sequelize's parameterized query API is available but is bypassed in critical routes (login, search). A separate PostgreSQL process with a minimal-privilege service account would limit SQL injection blast radius.

**Boundary 4 (Browser to Angular):** Angular's DomSanitizer is a framework-level defense that works by default. The `bypassSecurityTrustHtml()` calls in three components are explicit decisions to disable this protection — removing them restores the defense without any new dependency.

---

## 7. Identified Security Controls

The following table catalogs all identified security controls with their implementation evidence and effectiveness rating. Each Missing rating was confirmed absent via code search.

**Gap summary:** The most critical control gaps are: (1) no secure password hashing — MD5 without salt makes credential dumps immediately crackable; (2) JWT signing keys and HMAC secrets hardcoded in source code with no secrets management; (3) Angular's XSS protection explicitly disabled in three components while JWT tokens are stored in XSS-accessible localStorage; (4) no server-side role enforcement on admin endpoints — any authenticated user calls admin APIs; (5) no security audit logging — login failures, privilege escalation, and data exports are untracked, making post-breach investigation impossible.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|----------------|
| IAM | JWT authentication (RS256) | [`lib/insecurity.ts:54-57`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) | 🔶 Weak | [T-001](#t-001), [T-003](#t-003) — key hardcoded; alg:none accepted |
| IAM | express-jwt middleware for route protection | [`server.ts:355-435`](vscode://file/home/mrohr/juice-shop/server.ts:355) | ⚠️ Partial | [T-003](#t-003) — library 8 major versions outdated |
| IAM | Role-based access control (4 roles) | [`lib/insecurity.ts:157-175`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:157) | 🔶 Weak | [T-019](#t-019) — roles not checked on admin endpoints |
| Authorization | isAuthorized() middleware | [`server.ts:355-435`](vscode://file/home/mrohr/juice-shop/server.ts:355) | ⚠️ Partial | [T-010](#t-010), [T-011](#t-011) — resource ownership not verified |
| Authorization | denyAll() for destructive ops | [`server.ts:370-395`](vscode://file/home/mrohr/juice-shop/server.ts:370) | ✅ Adequate | Blocks DELETE/PUT on sensitive resources; consistently applied |
| Data Protection | Password hashing | [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) | 🔶 Weak | [T-008](#t-008) — MD5 without salt; not a password hash function |
| Data Protection | HTTPS (TLS) | Not enforced in default deployment | ❌ Missing | All traffic in cleartext in default Docker deployment |
| Input Validation | sanitize-html for HTML content | [`lib/insecurity.ts:62-73`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:62) | 🔶 Weak | [T-007](#t-007) — explicitly bypassed by three Angular components |
| Input Validation | sanitize-filename for uploads | [`lib/insecurity.ts:64`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:64) | ⚠️ Partial | Prevents null byte and traversal in filenames; no magic byte check |
| Input Validation | SQL parameterization | Not applied to login or search | ❌ Missing | [T-002](#t-002), [T-004](#t-004) — raw SQL string interpolation in critical routes |
| Input Validation | NoSQL query safety | Not applied to reviews | ❌ Missing | [T-009](#t-009) — $where with string concatenation |
| Audit & Logging | Morgan HTTP access log | [`server.ts:338`](vscode://file/home/mrohr/juice-shop/server.ts:338) | ⚠️ Partial | HTTP-level logging only; no security events (login failures, escalation) |
| Audit & Logging | Security audit log | Not implemented | ❌ Missing | [T-027](#t-027) — no record of login attempts, admin actions, data exports |
| Infrastructure | Helmet.js (noSniff + frameguard) | [`server.ts:185-186`](vscode://file/home/mrohr/juice-shop/server.ts:185) | ⚠️ Partial | X-Content-Type-Options and X-Frame-Options set; CSP and XSS filter not configured |
| Infrastructure | Content Security Policy | Not configured | ❌ Missing | [T-023](#t-023) — no browser-side script restriction |
| Infrastructure | CORS | [`server.ts:182`](vscode://file/home/mrohr/juice-shop/server.ts:182) | 🔶 Weak | [T-022](#t-022) — wildcard origin; all cross-origin requests permitted |
| Infrastructure | Rate limiting | [`server.ts:343-348`](vscode://file/home/mrohr/juice-shop/server.ts:343) | 🔶 Weak | [T-020](#t-020) — only on password reset; bypassable via X-Forwarded-For spoofing |
| Security Testing | CodeQL static analysis | [`.github/workflows/codeql-analysis.yml`](vscode://file/home/mrohr/juice-shop/.github/workflows/codeql-analysis.yml) | ✅ Adequate | Automated SAST runs on push; covers SQL injection, XSS patterns |
| Dependency | Dependabot dependency alerts | [`.dependabot/config.yml`](vscode://file/home/mrohr/juice-shop/.dependabot/config.yml) | ⚠️ Partial | Alerts configured but severely outdated libraries (express-jwt 0.1.3, jsonwebtoken 0.4.0) remain |
| Secrets Management | Secret handling | Hardcoded in source | ❌ Missing | [T-001](#t-001), [T-028](#t-028), [T-029](#t-029) — three secrets in public source code |


---

## 8. Threat Register

Risk Distribution: **Critical: 7** | **High: 12** | **Medium: 10** | **Low: 1**

STRIDE Coverage: Spoofing: 4 | Tampering: 7 | Repudiation: 1 | Information Disclosure: 8 | Denial of Service: 2 | Elevation of Privilege: 8

### 8.1 Critical (7)

Critical threats represent confirmed, exploitable vulnerabilities with high likelihood and maximum impact. These require immediate remediation.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | Auth Service | Tampering | Hardcoded 1024-bit RSA private key embedded in source at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23). Any attacker with read access to the repo can sign arbitrary JWTs as any user including admin. CWE-321. | High | Critical | 🔴 Critical | None — key is committed in plaintext | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | Auth Service | Tampering | SQL injection in login endpoint at [routes/login.ts:44](vscode://file/home/mrohr/juice-shop/routes/login.ts:44). String interpolation of `req.body.email` into raw SQL enables authentication bypass (`' OR 1=1--`), full credential dump, and account takeover. CWE-89. | High | Critical | 🔴 Critical | None — raw string interpolation | [M-002](#m-002) |
| <a id="t-003"></a>T-003 | Auth Service | Elevation of Privilege | JWT algorithm confusion: [lib/insecurity.ts:57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) calls `jws.verify(token, publicKey)` via an outdated library that accepts `alg:none`. Attacker strips signature and sets `alg:none` to forge tokens for any user. CWE-347. | High | Critical | 🔴 Critical | None — alg:none accepted by jws | [M-003](#m-003) |
| <a id="t-004"></a>T-004 | REST API | Information Disclosure | SQL injection in search endpoint at [routes/search.ts:23](vscode://file/home/mrohr/juice-shop/routes/search.ts:23). Attacker uses UNION SELECT to exfiltrate entire Users table including MD5 password hashes, email addresses, and security answers. CWE-89. | High | Critical | 🔴 Critical | None — raw string interpolation | [M-004](#m-004) |
| <a id="t-005"></a>T-005 | REST API | Elevation of Privilege | Remote Code Execution via B2B order endpoint at [routes/b2bOrder.ts:22](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:22). `vm.runInContext` with notevil sandbox is bypassable via prototype pollution, enabling arbitrary OS command execution on the server. CWE-94. | High | Critical | 🔴 Critical | Sandbox attempted; timeout=2000ms | [M-005](#m-005) |
| <a id="t-006"></a>T-006 | File Processor | Information Disclosure | XXE injection via libxmljs2 with `noent:true` enabled at [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts). Attacker submits XML with external entity referencing `/etc/passwd` or internal service URLs, reading server files or triggering SSRF. CWE-611. | High | Critical | 🔴 Critical | File type check only; noent:true enabled | [M-006](#m-006) |
| <a id="t-007"></a>T-007 | Angular SPA | Tampering | Stored XSS via `bypassSecurityTrustHtml` at [frontend/src/app/about/about.component.ts:119](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119), [administration.component.ts:60,78](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60), and [last-login-ip.component.ts:39](vscode://file/home/mrohr/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.ts:39). Stored feedback/review/IP rendered as raw HTML enables session hijacking. CWE-79. | High | Critical | 🔴 Critical | Angular DomSanitizer bypassed explicitly | [M-007](#m-007) |

### 8.2 High (12)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-008"></a>T-008 | Auth Service | Information Disclosure | MD5 password hashing without salt at [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43). Combined with T-004 SQLi dump, attacker cracks all passwords in minutes using rainbow tables. CWE-916. | High | High | 🟠 High | None — MD5, no salt | [M-008](#m-008) |
| <a id="t-009"></a>T-009 | REST API | Information Disclosure | NoSQL injection at [routes/showProductReviews.ts:36](vscode://file/home/mrohr/juice-shop/routes/showProductReviews.ts:36) via `$where: 'this.product == ' + id`. Attacker injects JavaScript expressions to read or manipulate all reviews across all products. CWE-943. | High | High | 🟠 High | None | [M-009](#m-009) |
| <a id="t-010"></a>T-010 | REST API | Elevation of Privilege | IDOR on basket endpoint at [routes/basket.ts:19](vscode://file/home/mrohr/juice-shop/routes/basket.ts:19). No ownership check: any authenticated user can read or modify any other user's basket by guessing/incrementing basket ID. CWE-284. | High | High | 🟠 High | Authentication required | [M-010](#m-010) |
| <a id="t-011"></a>T-011 | REST API | Information Disclosure | IDOR on data export at [routes/dataExport.ts:26](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26). `req.body.UserId` is trusted without comparing to the authenticated session, allowing exfiltration of any user's order history, memories, and profile data. CWE-639. | High | High | 🟠 High | Authentication required | [M-011](#m-011) |
| <a id="t-012"></a>T-012 | File Processor | Information Disclosure | SSRF at [routes/profileImageUrlUpload.ts:22](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:22). `fetch(url)` with raw user-supplied URL enables requests to internal metadata services (`169.254.169.254`), internal APIs, or arbitrary external hosts. CWE-918. | High | High | 🟠 High | None | [M-012](#m-012) |
| <a id="t-013"></a>T-013 | Data Access | Information Disclosure | `/encryptionkeys` directory served publicly at [server.ts:277](vscode://file/home/mrohr/juice-shop/server.ts:277) via `serveIndex`. Exposes RSA public key and any stored encryption keys to unauthenticated users, enabling cryptanalysis. CWE-552. | High | High | 🟠 High | None — unauthenticated | [M-013](#m-013) |
| <a id="t-014"></a>T-014 | Data Access | Information Disclosure | `/ftp` directory served publicly at [server.ts:269](vscode://file/home/mrohr/juice-shop/server.ts:269). Exposes confidential documents, acquisition letters, and other sensitive files to all unauthenticated visitors. CWE-552. | High | High | 🟠 High | None — unauthenticated | [M-013](#m-013) |
| <a id="t-015"></a>T-015 | Angular SPA | Information Disclosure | JWT stored in `localStorage` at [frontend/src/app/Services/request.interceptor.ts:13](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13). When combined with XSS (T-007), attacker JavaScript can read the token and authenticate as the victim from any origin. CWE-922. | High | High | 🟠 High | None — localStorage is XSS-accessible | [M-015](#m-015) |
| <a id="t-016"></a>T-016 | Angular SPA | Elevation of Privilege | Angular route guards are frontend-only; backend does not enforce role requirements on admin routes. An attacker bypassing the SPA (via direct API calls) accesses administrative features without the `admin` role. CWE-602. | High | High | 🟠 High | Frontend route guards only | [M-016](#m-016) |
| <a id="t-018"></a>T-018 | Data Access | Information Disclosure | SQLite database file `data/juiceshop.sqlite` is in-process with the application. A path traversal or file read vulnerability directly exposes the entire database. No encryption at rest. CWE-312. | Medium | High | 🟠 High | None — no encryption at rest | [M-017](#m-017) |
| <a id="t-019"></a>T-019 | Data Access | Information Disclosure | Hardcoded HMAC signing key `pa4qacea4VK9t9nGv7yZtwmj` at [lib/insecurity.ts:44](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44). Attacker who reads source can forge any HMAC-authenticated value in the system. CWE-321. | High | High | 🟠 High | None — hardcoded | [M-018](#m-018) |
| <a id="t-025"></a>T-025 | File Processor | Elevation of Privilege | ZIP path traversal in complaint upload at [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts). Path check uses `includes()` instead of `startsWith()`, allowing `../../` entries to write files outside the uploads directory. CWE-22. | High | High | 🟠 High | Weak path check (includes vs startsWith) | [M-019](#m-019) |

### 8.3 Medium (10)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-017"></a>T-017 | Auth Service | Spoofing | Security question password reset accepts answers compared with `===` but questions are predictable (mother's maiden name, pet name). Attacker uses social engineering or public OSINT to reset accounts without knowing the original password. CWE-640. | Medium | Medium | 🟡 Medium | Security questions implemented | [M-020](#m-020) |
| <a id="t-020"></a>T-020 | Auth Service | Elevation of Privilege | No JWT revocation mechanism. When a user logs out or changes password, previously issued tokens remain valid for up to 6 hours. A stolen token cannot be invalidated. CWE-613. | Medium | Medium | 🟡 Medium | 6-hour expiry | [M-021](#m-021) |
| <a id="t-021"></a>T-021 | REST API | Spoofing | Open redirect via `?to=` parameter. Attacker crafts phishing URL on the legitimate Juice Shop domain that redirects users to a malicious site to harvest credentials. CWE-601. | Medium | Medium | 🟡 Medium | None | [M-022](#m-022) |
| <a id="t-022"></a>T-022 | REST API | Information Disclosure | Unauthenticated `/metrics` endpoint at [server.ts:718](vscode://file/home/mrohr/juice-shop/server.ts:718) exposes Prometheus metrics including application internals, route counts, and potentially request rates that aid attack planning. CWE-200. | Medium | Medium | 🟡 Medium | None | [M-023](#m-023) |
| <a id="t-023"></a>T-023 | Angular SPA | Information Disclosure | No Content Security Policy configured. [server.ts:187](vscode://file/home/mrohr/juice-shop/server.ts:187) has CSP commented out. Without CSP, successful XSS can load external payloads, exfiltrate data to arbitrary origins, and persist across sessions. CWE-1021. | High | Medium | 🟡 Medium | None — CSP disabled | [M-007](#m-007) |
| <a id="t-024"></a>T-024 | Angular SPA | Information Disclosure | CORS wildcard `app.use(cors())` at [server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182) allows any origin to make credentialed cross-site requests, enabling CSRF-like attacks from malicious sites when combined with cookie authentication. CWE-942. | Medium | Medium | 🟡 Medium | None — wildcard | [M-014](#m-014) |
| <a id="t-026"></a>T-026 | Data Access | Repudiation | No audit log for security-critical operations (login, privilege changes, admin actions, data exports). Attackers can perform reconnaissance and exfiltration without any forensic trail. CWE-778. | Medium | Medium | 🟡 Medium | None | [M-013](#m-013) |
| <a id="t-027"></a>T-027 | File Processor | Spoofing | File upload validates only MIME type and extension, not actual file content (magic bytes). Attacker uploads a crafted `.jpg` containing PHP/shell content that may execute if a misconfigured web server processes it. CWE-434. | Medium | Medium | 🟡 Medium | Extension and MIME check | [M-006](#m-006) |
| <a id="t-028"></a>T-028 | Data Access | Tampering | Hardcoded cookie parser secret `kekse` at [server.ts:289](vscode://file/home/mrohr/juice-shop/server.ts:289). An attacker who reads the source can forge signed cookies, potentially bypassing session integrity checks. CWE-321. | Medium | Medium | 🟡 Medium | None — hardcoded | [M-018](#m-018) |
| <a id="t-030"></a>T-030 | REST API | Denial of Service | Global `sleep()` function defined at [routes/showProductReviews.ts:16](vscode://file/home/mrohr/juice-shop/routes/showProductReviews.ts:16) can be invoked via the NoSQL injection vector (T-009) to block the Node.js event loop for arbitrary duration, causing full application DoS. CWE-400. | Medium | High | 🟡 Medium | None | [M-009](#m-009) |

### 8.4 Low (1)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-029"></a>T-029 | Data Access | Information Disclosure | Application version disclosed in `/rest/admin/application-version` response at [server.ts:604](vscode://file/home/mrohr/juice-shop/server.ts:604). Version string aids attacker fingerprinting for targeted CVE exploitation. CWE-200. | Low | Low | 🟢 Low | Admin role check | [M-023](#m-023) |


---

## 9. Critical Findings

Seven Critical-risk threats were identified, all confirmed exploitable with direct evidence in the codebase. The following attack chain illustrates how they combine:

```mermaid
graph TD
    A["Attacker reads source repo"] -->|"RSA key exposed"| B["Forge JWT as admin\n(T-001, T-003)"]
    A -->|"SQLi in /rest/user/login"| C["Bypass auth entirely\n(T-002)"]
    B --> D["Access admin panel\n(T-016)"]
    C --> E["Dump Users table via UNION SELECT\n(T-004)"]
    E -->|"MD5 hashes cracked"| F["Mass account takeover\n(T-008)"]
    D -->|"Submit B2B XML order"| G["RCE via vm sandbox escape\n(T-005)"]
    D -->|"Upload XML complaint"| H["XXE: read /etc/passwd\n(T-006)"]
    C -->|"Submit feedback as any user"| I["Stored XSS via bypassSecurityTrustHtml\n(T-007)"]
    I -->|"Steal JWT from localStorage"| F
```

**Key takeaway:** A single credential (or no credential, via SQLi bypass) grants an attacker a path to server-level code execution or full user database exfiltration.

**Quick reference:**

| Threat | STRIDE | Risk | Mitigation |
|--------|--------|------|-----------|
| [T-001 Hardcoded RSA private key](#t-001) | Tampering | 🔴 Critical | [M-001](#m-001) |
| [T-002 Login SQL injection](#t-002) | Tampering | 🔴 Critical | [M-002](#m-002) |
| [T-003 JWT alg:none](#t-003) | Elevation of Privilege | 🔴 Critical | [M-003](#m-003) |
| [T-004 Search SQL injection](#t-004) | Information Disclosure | 🔴 Critical | [M-004](#m-004) |
| [T-005 B2B RCE via vm sandbox](#t-005) | Elevation of Privilege | 🔴 Critical | [M-005](#m-005) |
| [T-006 XXE via libxmljs2](#t-006) | Information Disclosure | 🔴 Critical | [M-006](#m-006) |
| [T-007 Stored XSS bypass](#t-007) | Tampering | 🔴 Critical | [M-007](#m-007) |

---

## 10. Mitigation Register

### P1 — Immediate

<a id="m-001"></a>**M-001 — Remove hardcoded RSA private key from source control**

**Addresses:** [T-001](#t-001)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** The private key committed at `lib/insecurity.ts:23` is accessible to anyone with repo access and cannot be rotated without a code change. All JWTs signed with it are permanently compromised.

**How:**
1. Remove the key from `lib/insecurity.ts` and add a `.gitignore` entry for `*.pem` / `*.key`.
2. Generate a fresh 4096-bit RSA key pair: `openssl genrsa -out jwt-private.pem 4096`
3. Load the key from an environment variable: `const privateKey = process.env.JWT_PRIVATE_KEY`
4. Rotate all existing JWT tokens (change the `JWT_KEY_ID` environment variable to invalidate all sessions).
5. Audit git history and use `git filter-repo` to purge the old key from all commits.

```typescript
// Before (insecure):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAI...'

// After (secure):
const privateKey = process.env.JWT_PRIVATE_KEY
if (\!privateKey) throw new Error('JWT_PRIVATE_KEY environment variable is required')
```

**Verification:** `grep -r "BEGIN RSA PRIVATE KEY" .` returns no results; `JWT_PRIVATE_KEY` is loaded from env and throws on startup if missing.

**Reference:** [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html), CWE-321

---

<a id="m-002"></a>**M-002 — Fix SQL injection in login endpoint**

**Addresses:** [T-002](#t-002)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** The raw string interpolation at `routes/login.ts:44` enables authentication bypass and full database access with a single request.

**How:**
1. Replace raw SQL string with Sequelize parameterized query using `replacements`.
2. Use `where` clause with Sequelize ORM operators instead of raw SQL.

```typescript
// Before (vulnerable):
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`
)

// After (secure):
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email, password: security.hash(req.body.password) },
    model: UserModel, plain: true }
)
```

**Verification:** Attempt login with email `' OR 1=1--` — returns 401. Run `npm run frisby` — all auth tests pass.

**Reference:** [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), CWE-89

---

<a id="m-003"></a>**M-003 — Upgrade JWT library and enforce RS256 algorithm**

**Addresses:** [T-003](#t-003)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** `express-jwt@0.1.3` and `jsonwebtoken@0.4.0` are from 2013–2014 and accept `alg:none`. Current versions enforce algorithm allowlists.

**How:**
1. Upgrade: `npm install jsonwebtoken@^9.0.0 express-jwt@^8.0.0`
2. Replace `jws.verify` with `jwt.verify` and explicitly specify `{ algorithms: ['RS256'] }`.
3. Remove the `jws` dependency entirely.

```typescript
// Before (vulnerable):
export const verify = (token: string) => token ? (jws.verify as any)(token, publicKey) : false

// After (secure):
import jwt from 'jsonwebtoken'
export const verify = (token: string) => {
  if (\!token) return false
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] })
}
```

**Verification:** Submit a JWT with `"alg":"none"` — server returns 401. All existing RS256 tokens still validate.

**Reference:** [JWT Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html), CWE-347

---

<a id="m-004"></a>**M-004 — Fix SQL injection in search endpoint**

**Addresses:** [T-004](#t-004)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** Raw string interpolation in `routes/search.ts:23` allows UNION SELECT to dump the entire database.

**How:**
1. Replace raw SQL with Sequelize ORM `Op.like` operators.
2. Use parameterized replacements if raw SQL is required for performance.

```typescript
// Before (vulnerable):
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL)`
)

// After (secure):
ProductModel.findAll({
  where: {
    [Op.and]: [
      { deletedAt: null },
      { [Op.or]: [
        { name: { [Op.like]: `%${criteria}%` } },
        { description: { [Op.like]: `%${criteria}%` } }
      ]}
    ]
  }
})
```

**Verification:** Submit `q='; DROP TABLE Products; --` — returns empty results, table intact. UNION SELECT returns no data outside Products.

**Reference:** CWE-89

---

<a id="m-005"></a>**M-005 — Remove vm sandbox and restrict B2B order processing**

**Addresses:** [T-005](#t-005)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Node.js `vm.runInContext` is not a security boundary; it is bypassable by design. The notevil sandbox has known prototype pollution bypasses.

**How:**
1. Remove `vm.runInContext` and `safeEval` from `routes/b2bOrder.ts`.
2. Parse the order data as a plain JSON structure with strict schema validation using `ajv`.
3. If expression evaluation is required, implement a whitelist allowlist of permitted operations.
4. Run the processing in a separate, sandboxed child process if arbitrary computation is needed.

```typescript
// Before (vulnerable):
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// After (secure):
import Ajv from 'ajv'
const ajv = new Ajv()
const schema = { type: 'array', items: { type: 'object', properties: {
  productId: { type: 'integer' },
  quantity: { type: 'integer', minimum: 1, maximum: 100 }
}, required: ['productId', 'quantity'], additionalProperties: false }}
const validate = ajv.compile(schema)
if (\!validate(orderLines)) throw new Error('Invalid order format')
```

**Verification:** Submit B2B order with `constructor.constructor('return process')()` — returns 400 validation error.

**Reference:** CWE-94, [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)

---

<a id="m-006"></a>**M-006 — Disable XXE and validate uploaded file content**

**Addresses:** [T-006](#t-006), [T-027](#t-027)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** `noent:true` in libxmljs2 enables external entity resolution. Combined with user-controlled XML, this reads arbitrary server files.

**How:**
1. Set `noent: false` in all libxmljs2 parse calls.
2. Add magic-byte file content validation (not just extension/MIME).
3. Consider replacing libxmljs2 with a safer JSON-only API for B2B orders.

```typescript
// Before (vulnerable):
libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

// After (secure):
libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })
```

**Verification:** Submit XML with `<\!DOCTYPE foo [<\!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` — entity is not resolved.

**Reference:** [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), CWE-611

---

<a id="m-007"></a>**M-007 — Remove bypassSecurityTrustHtml calls and enable CSP**

**Addresses:** [T-007](#t-007), [T-023](#t-023)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Explicitly bypassing Angular's sanitizer on user-controlled content (feedback comments, IP addresses) enables persistent XSS that can steal sessions from all visitors.

**How:**
1. Remove `bypassSecurityTrustHtml` from `about.component.ts:119`, `administration.component.ts:60,78`, and `last-login-ip.component.ts:39`.
2. Use Angular's `innerText` binding (`[innerText]="comment"`) instead of `[innerHTML]`.
3. If HTML rendering is required, implement a strict allowlist sanitizer.
4. Enable a strict CSP in `server.ts` (currently commented out at line 187):

```typescript
// In server.ts — enable helmet CSP:
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"]
  }
}))
```

**Verification:** Submit feedback with `<script>alert(1)</script>` — script tag rendered as escaped text, not executed. CSP header present in HTTP responses.

**Reference:** [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), CWE-79

---

### P2 — This Sprint

<a id="m-008"></a>**M-008 — Replace MD5 with bcrypt for password hashing**

**Addresses:** [T-008](#t-008)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** MD5 is cryptographically broken and unsalted. Rainbow table attacks crack MD5 password hashes in seconds.

**How:**
1. Replace `crypto.createHash('md5')` with `bcrypt.hash(password, 12)` in `lib/insecurity.ts:43`.
2. Add a migration to rehash passwords on next login (lazy migration pattern).
3. Update login comparison to use `bcrypt.compare`.

```typescript
// Before:
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After:
import bcrypt from 'bcrypt'
export const hashPassword = async (password: string) => bcrypt.hash(password, 12)
export const verifyPassword = async (password: string, hash: string) => bcrypt.compare(password, hash)
```

**Verification:** New passwords stored as `$2b$12$...` in database. Existing MD5 hashes migrated on first login. `npm test` passes.

**Reference:** [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), CWE-916

---

<a id="m-009"></a>**M-009 — Fix NoSQL injection and remove global sleep function**

**Addresses:** [T-009](#t-009), [T-030](#t-030)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The `$where` operator with string concatenation allows arbitrary JavaScript execution in the MongoDB-compatible store. The global `sleep()` function enables event-loop blocking DoS.

**How:**
1. Replace `$where` with a standard query operator in `routes/showProductReviews.ts:36`.
2. Remove the `global.sleep` definition at line 16.

```typescript
// Before (vulnerable):
db.reviewsCollection.find({ $where: 'this.product == ' + id })

// After (secure):
db.reviewsCollection.find({ product: parseInt(id, 10) })
```

**Verification:** Submit `id=1;sleep(10000)` — request completes immediately without delay. Event loop not blocked.

**Reference:** CWE-943

---

<a id="m-010"></a>**M-010 — Add ownership check to basket endpoint**

**Addresses:** [T-010](#t-010)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**How:**
1. Add `UserId` condition to the basket lookup in `routes/basket.ts:19`.

```typescript
// Before (IDOR):
const basket = await BasketModel.findOne({ where: { id }, include: [...] })

// After (secure):
const basket = await BasketModel.findOne({
  where: { id, UserId: (req as any).user.data.id },
  include: [...]
})
```

**Verification:** Authenticated user requesting another user's basket ID receives 403. Own basket accessible normally.

**Reference:** CWE-284

---

<a id="m-011"></a>**M-011 — Fix data export IDOR**

**Addresses:** [T-011](#t-011)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**How:**
1. Ignore `req.body.UserId` in `routes/dataExport.ts:26` and use the authenticated session user ID instead.

```typescript
// Before (IDOR):
memories = await MemoryModel.findAll({ where: { UserId: req.body.UserId } })

// After (secure):
const loggedInUserId = (req as any).user.data.id
memories = await MemoryModel.findAll({ where: { UserId: loggedInUserId } })
```

**Verification:** Authenticated user requesting export with another user's ID receives only their own data.

**Reference:** CWE-639

---

<a id="m-012"></a>**M-012 — Add SSRF protection to profile image URL upload**

**Addresses:** [T-012](#t-012)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**How:**
1. Validate the URL scheme (https only) and block RFC-1918 / link-local IP ranges before fetching.
2. Use a DNS rebinding-safe HTTP client or an allowlist of permitted domains.

```typescript
// In routes/profileImageUrlUpload.ts:
import { URL } from 'url'
function isSafeUrl (rawUrl: string): boolean {
  try {
    const u = new URL(rawUrl)
    if (\!['https:'].includes(u.protocol)) return false
    const forbidden = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)/
    return \!forbidden.test(u.hostname)
  } catch { return false }
}
if (\!isSafeUrl(url)) return res.status(400).json({ error: 'URL not allowed' })
```

**Verification:** Submit `http://169.254.169.254/latest/meta-data/` — returns 400. Valid HTTPS image URL succeeds.

**Reference:** [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), CWE-918

---

<a id="m-013"></a>**M-013 — Restrict sensitive directories and add audit logging**

**Addresses:** [T-013](#t-013), [T-014](#t-014), [T-026](#t-026)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**How:**
1. Remove or add authentication middleware to `/ftp` and `/encryptionkeys` routes in `server.ts:269,277`.
2. Add structured audit logging for auth events, privilege changes, and data exports using `winston` or `pino`.

```typescript
// Remove public directory listings:
// app.use('/ftp', serveIndex('ftp', { icons: true }))         // DELETE
// app.use('/encryptionkeys', serveIndex('encryptionkeys', ...)) // DELETE

// Add audit logger:
import pino from 'pino'
const auditLog = pino({ level: 'info' }, pino.destination('/var/log/juiceshop-audit.log'))
app.use((req, res, next) => {
  if (['/rest/user/login', '/rest/user/change-password'].includes(req.path)) {
    res.on('finish', () => auditLog.info({ event: 'auth', path: req.path, status: res.statusCode, ip: req.ip }))
  }
  next()
})
```

**Verification:** `curl http://localhost:3000/ftp` returns 401. Auth events appear in audit log.

**Reference:** CWE-552, CWE-778

---

<a id="m-014"></a>**M-014 — Restrict CORS to known origins**

**Addresses:** [T-024](#t-024)
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Low

**How:**
1. Replace `app.use(cors())` with an explicit origin allowlist in `server.ts:182`.

```typescript
// Before:
app.use(cors())

// After:
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') ?? ['http://localhost:3000'],
  credentials: true
}))
```

**Verification:** Cross-origin request from `http://evil.example` receives `Access-Control-Allow-Origin` omitted or error. Legitimate origin succeeds.

**Reference:** CWE-942

---

<a id="m-015"></a>**M-015 — Move JWT from localStorage to httpOnly cookie**

**Addresses:** [T-015](#t-015)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** `localStorage` is accessible to any JavaScript on the page. An XSS payload can exfiltrate the JWT to a remote server.

**How:**
1. Set the JWT as an `httpOnly; Secure; SameSite=Strict` cookie from the server response.
2. Remove the `localStorage.setItem('token', ...)` calls in the Angular frontend.
3. Update `request.interceptor.ts` to send credentials via cookie rather than Authorization header.

**Verification:** After login, token does not appear in `localStorage`. DevTools Application tab shows `httpOnly` cookie. XSS payload `document.cookie` does not contain the JWT.

**Reference:** [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), CWE-922

---

<a id="m-016"></a>**M-016 — Enforce role-based authorization on all admin API endpoints**

**Addresses:** [T-016](#t-016)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**How:**
1. Add an `isAdmin` middleware check to all admin routes in `server.ts`.
2. Verify JWT role claim on the server side for every admin endpoint.

```typescript
const isAdmin = (req: Request, res: Response, next: NextFunction) => {
  const user = (req as any).user
  if (\!user?.data?.role || user.data.role \!== 'admin') {
    return res.status(403).json({ error: 'Forbidden' })
  }
  next()
}

// Apply to admin routes:
app.get('/rest/admin/application-version', isAdmin, retrieveAppVersion())
app.get('/rest/admin/application-configuration', isAdmin, retrieveAppConfiguration())
```

**Verification:** Non-admin JWT requesting `/rest/admin/*` returns 403. Admin JWT succeeds.

**Reference:** CWE-602

---

### P3 — Next Quarter

<a id="m-017"></a>**M-017 — Enable SQLite encryption at rest**

**Addresses:** [T-018](#t-018)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟠 High
**Effort:** High

**How:**
1. Replace `sqlite3` with `@journeyapps/sqlcipher` or `better-sqlite3-multiple-ciphers`.
2. Provide encryption key via environment variable, not hardcoded.
3. Encrypt the existing database: `sqlite3-cipher data/juiceshop.sqlite "ATTACH 'encrypted.db' AS encrypted KEY $DB_KEY; SELECT sqlcipher_export('encrypted'); DETACH DATABASE encrypted;"`

**Verification:** `strings data/juiceshop.sqlite | grep -i password` returns no results (data encrypted).

**Reference:** CWE-312

---

<a id="m-018"></a>**M-018 — Remove all hardcoded secrets**

**Addresses:** [T-019](#t-019), [T-028](#t-028)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟠 High
**Effort:** Low

**How:**
1. Replace hardcoded HMAC key at `lib/insecurity.ts:44` with `process.env.HMAC_KEY`.
2. Replace hardcoded cookie secret at `server.ts:289` with `process.env.COOKIE_SECRET`.
3. Add startup validation to throw if either is missing or less than 32 characters.
4. Rotate all HMAC-signed values and sessions after deployment.

```typescript
// lib/insecurity.ts — before:
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')

// After:
const hmacKey = process.env.HMAC_KEY
if (\!hmacKey || hmacKey.length < 32) throw new Error('HMAC_KEY must be at least 32 chars')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacKey)
```

**Verification:** `grep -r "pa4qacea4VK9t9nGv7yZtwmj\|kekse" .` returns no matches. App fails to start without env vars set.

**Reference:** CWE-321

---

<a id="m-019"></a>**M-019 — Fix ZIP path traversal in complaint upload**

**Addresses:** [T-025](#t-025)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟠 High
**Effort:** Low

**How:**
1. Replace `includes()` with `startsWith()` in the path safety check in `routes/fileUpload.ts`.
2. Use `path.resolve()` on both sides and assert the resolved path starts with the target directory.

```typescript
// Before (vulnerable):
if (absolutePath.includes(path.resolve('.'))) { // path traversal possible

// After (secure):
const targetDir = path.resolve('uploads/complaints') + path.sep
if (\!absolutePath.startsWith(targetDir)) {
  throw new Error('Path traversal detected')
}
```

**Verification:** Upload a ZIP containing `../../etc/cron.d/evil` — extraction rejected with error. Valid ZIP extracts normally.

**Reference:** CWE-22

---

<a id="m-020"></a>**M-020 — Replace security questions with TOTP/email-based reset**

**Addresses:** [T-017](#t-017)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** High

**How:**
1. Remove security question-based reset flow.
2. Implement time-limited email reset token: generate 32-byte random token, hash it, store in DB with 15-minute expiry.
3. Send reset link to verified email. Validate token on reset.

**Verification:** Attempting password reset without email access fails. Valid reset link expires after 15 minutes.

**Reference:** [OWASP Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html), CWE-640

---

<a id="m-021"></a>**M-021 — Implement JWT revocation via token blocklist**

**Addresses:** [T-020](#t-020)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Medium

**How:**
1. On logout or password change, add the JWT `jti` claim to a Redis blocklist with TTL equal to token expiry.
2. Add middleware to check the blocklist before processing any authenticated request.

**Verification:** Logout revokes token immediately. Reuse of the old token returns 401 even within the 6-hour window.

**Reference:** CWE-613

---

### P4 — Backlog

<a id="m-022"></a>**M-022 — Fix open redirect**

**Addresses:** [T-021](#t-021)
**Priority:** **P4 — Backlog**
**Severity:** 🟡 Medium
**Effort:** Low

**How:**
1. Validate the `?to=` redirect target against an explicit allowlist of paths.
2. Reject or strip absolute URLs and protocol-relative URLs.

```typescript
const ALLOWED_REDIRECTS = ['/search', '/about', '/contact']
const to = req.query.to as string
if (\!ALLOWED_REDIRECTS.includes(to)) return res.redirect('/')
res.redirect(to)
```

**Verification:** `?to=https://evil.com` redirects to `/` instead. Allowlisted paths work normally.

**Reference:** CWE-601

---

<a id="m-023"></a>**M-023 — Restrict /metrics endpoint and suppress version disclosure**

**Addresses:** [T-022](#t-022), [T-029](#t-029)
**Priority:** **P4 — Backlog**
**Severity:** 🟡 Medium
**Effort:** Low

**How:**
1. Add IP-based or token-based authentication to `/metrics` route in `server.ts:718`.
2. Remove or obfuscate version information from `/rest/admin/application-version` response.

**Verification:** Unauthenticated request to `/metrics` returns 401. Version endpoint returns generic string or 404.

**Reference:** CWE-200

---

## 11. Out of Scope

The following areas were not analyzed in this assessment:

- **Infrastructure / hosting environment**: No cloud provider, container orchestration, or network topology was examined. Security controls at the infrastructure layer (VPC, firewall rules, IAM roles) are not assessed.
- **Third-party integrations**: The Juice Shop uses PayPal sandbox and other external service configurations that were not tested.
- **CI/CD pipeline security**: GitHub Actions workflows, branch protection rules, and supply chain controls were not reviewed.
- **Mobile clients**: No mobile application surfaces exist; out of scope by definition.
- **Cryptographic key management HSMs**: No hardware security module configuration is present; recommendations assume environment variable-based key injection.
- **Internationalization (i18n) strings**: Translation files and Crowdin integration were not reviewed for injection risks.
- **Challenge correctness**: This assessment treats the intentional vulnerabilities as real findings. Whether specific challenges are correctly implemented or solvable is a separate concern for contributors.
- **Performance and availability under load**: Denial of Service findings are limited to code-level issues (event loop blocking, missing rate limits). Volumetric DDoS is out of scope.


---

## Appendix: Run Statistics

### Run Metadata

| Field | Value |
|-------|-------|
| Generated | 2026-04-14T12:00:00Z |
| Invocation | `/create-threat-model --stride-model opus --full --verbose` |
| Assessment Mode | Full (--full) |
| Plugin Version | appsec-plugin 0.9.0-beta (analysis v1) |
| Assessment Depth | standard (components: 5, STRIDE turns: 15/22/31) |
| Repository | `/home/mrohr/juice-shop` |
| Baseline SHA | n/a (first full run) |
| Current SHA | `7380ce7120e289fc6bea861efd3fcba89261a6a8` |

### Agents & Models

| Agent | Model | Role | Phases |
|-------|-------|------|--------|
| threat-analyst | claude-sonnet-4-6 | Orchestrator — architecture, controls, synthesis, finalization | 1, 3-8, 10-11 |
| recon-scanner | claude-sonnet-4-6 | Tech stack and security pattern reconnaissance | 2 |
| stride-analyzer | claude-opus-4-6 | Per-component STRIDE threat analysis | 9 (5 instances) |
| qa-reviewer | claude-sonnet-4-6 | Cross-reference validation, link fixes, consistency | Post-assessment |

### Phase Duration Breakdown

| Phase | Description | Agent(s) | Duration |
|-------|-------------|----------|----------|
| Phase 1 | Context Resolution | threat-analyst (sonnet-4-6) [cache hit] | 0m 00s |
| Phase 2 | Reconnaissance | recon-scanner (sonnet-4-6) | 1m 52s |
| Phase 3 | Architecture Modeling (4 diagrams) | threat-analyst (sonnet-4-6) | 0m 27s |
| Phase 4 | Security Use Cases | threat-analyst (sonnet-4-6) | (inline) |
| Phase 5 | Asset Identification | threat-analyst (sonnet-4-6) | (inline) |
| Phase 6 | Attack Surface Mapping | threat-analyst (sonnet-4-6) | (inline) |
| Phase 7 | Trust Boundary Analysis | threat-analyst (sonnet-4-6) | (inline) |
| Phase 8 | Security Controls Catalog | threat-analyst (sonnet-4-6) | (inline) |
| Phase 9 | STRIDE Threat Enumeration (5 components) | 5 x stride-analyzer (opus-4-6) | 2m 57s |
| Phase 10 | Scan Synthesis | threat-analyst (sonnet-4-6) | (inline) |
| Phase 11 | Finalization (YAML + MD composition) | threat-analyst (sonnet-4-6) | 38m 21s |
| **Assessment Total** | | | **44m 20s** |
| QA Review | Cross-reference validation, link fixes, consistency checks | qa-reviewer (sonnet-4-6) | 0m 58s |
| **Grand Total** | | | **45m 18s** |

> Phases 3-8 ran inline (same timestamp). Phase 9 dispatched 5 STRIDE analyzers in parallel. The Assessment Total reflects wall-clock time from ASSESSMENT_START to ASSESSMENT_END.

### Token Consumption

| Category | Tokens |
|----------|--------|
| Input | 56 |
| Output | 19,215 |
| Cache Write | 170,160 |
| Cache Read | 1,487,042 |
| **Total** | **1,676,473** |

> Host-session tokens only. Sub-agent tokens (stride-analyzer) are executed within the host session and included in these totals.

### Cost Estimate

| Metric | sonnet-4-6 | opus-4-6 |
|--------|------------|----------|
| With prompt caching | ~$1.37 | ~$6.90 |
| Without prompt caching | ~$2.27 | ~$11.36 |
| Cache savings | 39.8% | 39.8% |

> Billing: subscription (estimated). Costs under each model's pricing are shown for reference since sub-agents may use different models. Actual billing depends on which model processed each token.

<details><summary>API pricing reference (per 1M tokens)</summary>

| Model | Input | Output | Cache Write | Cache Read |
|-------|-------|--------|-------------|------------|
| claude-sonnet-4-6 | $3.00 | $15.00 | $3.75 | $0.30 |
| claude-opus-4-6 | $15.00 | $75.00 | $18.75 | $1.50 |
| claude-haiku-4-5 | $0.80 | $4.00 | $1.00 | $0.08 |

</details>

### Coverage Summary

| Metric | Count |
|--------|-------|
| Components analyzed | 5 (auth-service, rest-api, frontend-spa, file-processor, data-access) |
| Total threats identified | 30 |
| Critical threats | 7 |
| High threats | 12 |
| Medium threats | 10 |
| Low threats | 1 |
| Mitigations generated | 23 |
