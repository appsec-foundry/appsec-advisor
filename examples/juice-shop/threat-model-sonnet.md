# Threat Model — OWASP Juice Shop

| Field | Value |
|-------|-------|
| Generated | 2026-04-12T09:37:26Z |
| Analysis Duration | 8 min 43 s |
| Analyst | appsec-threat-analyst (Claude) |
| Model | claude-sonnet-4-6 |
| Agent Models | all agents: claude-sonnet-4-6 |
| Mode | full |
| Baseline SHA | 7380ce7120e289fc6bea861efd3fcba89261a6a8 |
| Current SHA | 7380ce7120e289fc6bea861efd3fcba89261a6a8 |
| Changed Files | 0 |
| Re-analyzed Components | 5 |
| Carried Forward | 0 |
| Changelog | see Changelog section (v1, 2026-04-12) |
| Context Sources | None |

---

## Changelog

> Append-only history of incremental updates to this threat model. Newest entry first.

### v1 — 2026-04-12 (full)

Initial full-scan assessment. 5 components analyzed: auth-service, rest-api, frontend-spa, file-upload, admin-api. 24 threats identified (7 Critical, 12 High, 5 Medium). 20 mitigations produced.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Containers](#22-containers)
   - [2.3 Technology Architecture](#23-technology-architecture)
   - [2.4 Security Architecture Assessment](#24-security-architecture-assessment)
3. [Assets](#3-assets)
4. [Attack Surface](#4-attack-surface)
   - [4.1 Unauthenticated Entry Points (11)](#41-unauthenticated-entry-points-11)
   - [4.2 Authenticated Entry Points (5)](#42-authenticated-entry-points-5)
5. [Trust Boundaries](#5-trust-boundaries)
6. [Identified Security Controls](#6-identified-security-controls)
7. [Threat Register](#7-threat-register)
   - [7.1 Critical (7)](#71-critical-7)
   - [7.2 High (12)](#72-high-12)
   - [7.3 Medium (5)](#73-medium-5)
   - [7.4 Low (0)](#74-low-0)
8. [Attack Walkthroughs](#8-attack-walkthroughs)
9. [Mitigation Register](#9-mitigation-register)
10. [Out of Scope](#10-out-of-scope)

---

## Management Summary

### Verdict

🔴 **Not production-ready.** OWASP Juice Shop is an intentionally vulnerable application — every STRIDE category is confirmed exploitable. Seven Critical findings allow unauthenticated full compromise in minutes. This threat model documents the complete vulnerability surface as a structured reference for training exercises.

### Top Risks

The table below lists the highest-severity findings sorted by risk level. All Critical findings require immediate remediation (P1); High findings should follow in the next cycle (P2).

| | ID | Risk | Impact | Mitigation | Effort |
|-|----|------|--------|------------|--------|
| 🔴 | [T-001](#t-001) | Hardcoded RSA Private Key | Any repo reader forges admin JWTs offline — full auth bypass | [M-001](#m-001) Externalize key to env/secret manager | Low |
| 🔴 | [T-002](#t-002) | SQL Injection in Login | Unauthenticated admin access via single crafted email | [M-002](#m-002) Parameterized queries | Low |
| 🔴 | [T-003](#t-003) | JWT Algorithm Confusion | jsonwebtoken 0.4.0 accepts unsigned tokens — auth bypass | [M-003](#m-003) Upgrade jsonwebtoken + enforce RS256 | Low |
| 🔴 | [T-006](#t-006) | SQL Injection in Search | Unauthenticated data dump via UNION SELECT | [M-002](#m-002) Parameterized queries | Low |
| 🔴 | [T-018](#t-018) | XXE in XML File Upload | Arbitrary local file read via libxmljs2 noent:true | [M-017](#m-017) Set noent:false | Low |
| 🔴 | [T-021](#t-021) | RCE via B2B Sandbox Escape | OS command execution via vm.createContext eval escape | [M-020](#m-020) Remove eval-based execution | Medium |
| 🔴 | [T-022](#t-022) | SSTI in User Profile | OS command execution via eval() in pug rendering | [M-020](#m-020) Remove eval-based execution | Medium |
| 🟠 | [T-005](#t-005) | MD5 Password Hashing | Extracted hashes crackable in minutes via GPU/rainbow tables | [M-005](#m-005) Replace with bcrypt | Low |
| 🟠 | [T-007](#t-007) | Systemic IDOR | Any authenticated user accesses other users' baskets, orders, recycles | [M-006](#m-006) Add ownership checks | Low |
| 🟠 | [T-013](#t-013) | Stored XSS via Angular bypass | Three components use bypassSecurityTrustHtml — persistent XSS | [M-013](#m-013) Remove trust bypasses | Low |
| 🟠 | [T-015](#t-015) | JWT in localStorage | Any XSS exfiltrates session token — full account takeover | [M-014](#m-014) Move to httpOnly cookie | Low |
| 🟠 | [T-019](#t-019) | ZIP Path Traversal | Crafted ZIP writes files outside uploads/ directory | [M-018](#m-018) Validate resolved paths | Low |

> 🔴 = Critical (P1 — fix immediately) · 🟠 = High (P2 — fix in next cycle)

<br/>

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

### ⚠ Worst Case Scenarios

**Complete system compromise** — An external attacker without credentials gains full control over the server, including the ability to read, modify, or delete all data and execute arbitrary commands on the host operating system. Multiple independent paths lead here:
- Forged admin session via leaked signing key ([T-001](#t-001)) → code execution ([T-021](#t-021))
- Login bypass via injection ([T-002](#t-002)) → code execution ([T-021](#t-021))
- Unauthenticated file read via malicious upload ([T-018](#t-018))

**Full customer data breach** — All user credentials, personal data, and payment information are extracted from the database. An attacker can achieve this in minutes through a single manipulated request ([T-002](#t-002), [T-006](#t-006)) — no prior access required.

**Mass account takeover** — An attacker plants persistent malicious content that silently steals the session of every user who visits the affected page, enabling takeover of all active accounts including administrators ([T-013](#t-013) → [T-015](#t-015)).

See [Critical Attack Chain](#critical-attack-chain) for a visual diagram of how these risks interconnect.

</blockquote>

<br/>

### Architecture Assessment

The architecture presents no meaningful security boundary at any layer. The single Express monolith handles all trust decisions at the application layer with no structural safety net.

| | Layer | Defect | Consequence | Enables |
|-|-------|--------|-------------|---------|
| 🔴 | **Authentication** | JWT private key hardcoded in source code | Any repo reader can forge arbitrary tokens offline | [T-001](#t-001) |
| 🔴 | **Sandboxing** | vm.createContext runs in-process, no seccomp/namespace isolation | Two confirmed escape paths to OS command execution | [T-021](#t-021), [T-022](#t-022) |
| 🔴 | **Perimeter** | No API gateway, WAF, or reverse proxy | Entire attack surface exposed directly on port 3000 — SQLi/XXE reachable unauthenticated | [T-002](#t-002), [T-018](#t-018) |
| 🟠 | **Cryptography** | MD5 password hashing without salt | Extracted hashes crackable in seconds via GPU/rainbow tables | [T-005](#t-005) |
| 🟠 | **Transport** | No TLS enforcement; CORS set to wildcard `*` | Traffic interceptable; any origin can make authenticated requests | [T-009](#t-009) |
| 🟠 | **Frontend** | No Content-Security-Policy header | XSS payloads execute unrestricted; session tokens exfiltratable from localStorage | [T-013](#t-013), [T-015](#t-015) |

> 🔴 = directly enables Critical findings · 🟠 = directly enables High findings

### Follow-up Actions (P2/P3)

The High findings above (🟠) already have mitigations assigned. The following additional hardening measures address Medium-risk findings and defense-in-depth gaps:

| Priority | Mitigation | Why |
|----------|-----------|-----|
| P2 | [M-016](#m-016) Implement CSP and security headers | No CSP header set globally — enables XSS escalation |
| P2 | [M-010](#m-010) Limit YAML expansion / add file size cap | YAML bomb crashes Node.js process (DoS) |
| P3 | [M-015](#m-015) Enforce admin role checks server-side | Client-side Angular route guards are bypassable |

### Operational Strengths

Despite the intentionally vulnerable design, the project does implement several security-relevant controls. None of them mitigate Critical findings, but they provide a foundation that a hardening effort could build on.

| Control | What it provides | Limitation |
|---------|-----------------|------------|
| ZAP DAST scan in CI | Automated vulnerability scanning on every build | Scan profile is baseline-only; does not cover authenticated attack paths or business logic flaws |
| CycloneDX SBOM generation | Machine-readable dependency inventory for supply-chain auditing | Generated at build time but no policy gate — known-vulnerable packages are not blocked |
| Morgan access logging | Combined-format HTTP request logging for incident investigation | Logs served unauthenticated at /support/logs; no centralized log shipping or alerting |
| Rate limiting (password reset) | Throttles brute-force attempts on /rest/user/reset-password | Only applied to one endpoint; login, registration, and file upload have no rate limits |
| Helmet (noSniff, frameguard) | Prevents MIME-sniffing and clickjacking via X-Frame-Options | CSP header not configured; HSTS not enabled — XSS and protocol downgrade remain possible |
| 2FA via TOTP | Optional second factor for user accounts | Opt-in only; not enforced for admin accounts; does not protect against JWT forgery via hardcoded key |

**Bottom line:** These controls demonstrate what *partial* coverage looks like. They reduce noise in automated scanners but provide no meaningful barrier against a targeted attacker exploiting the Critical findings documented above.

---

## Critical Attack Chain

The seven Critical findings can be chained into two independent full-compromise paths. An unauthenticated attacker needs only one of the first three findings to gain admin access; once authenticated, the RCE findings complete the chain.

```mermaid
graph LR
    ATK["Attacker\n(unauthenticated)"]:::risk
    T001["T-001\nHardcoded RSA Key"]:::risk
    T002["T-002\nSQL Injection Login"]:::risk
    T003["T-003\nJWT alg:none"]:::risk
    T006["T-006\nSQL Injection Search"]:::risk
    T018["T-018\nXXE File Upload"]:::risk
    T021["T-021\nRCE B2B Eval"]:::risk
    T022["T-022\nRCE SSTI"]:::risk
    ADMIN["Admin Access\n+ Data Dump"]:::risk
    RCE["OS Code Execution\nFull Compromise"]:::risk

    ATK -->|"read source repo"| T001
    ATK -->|"craft email payload"| T002
    ATK -->|"craft alg:none token"| T003
    ATK -->|"UNION SELECT"| T006
    ATK -->|"upload XML with XXE"| T018
    T001 -->|"forge admin JWT"| ADMIN
    T002 -->|"bypass auth"| ADMIN
    T003 -->|"bypass verification"| ADMIN
    T006 -->|"dump Users table"| ADMIN
    T018 -->|"read /etc/passwd"| ADMIN
    ADMIN -->|"POST /b2b/v2/orders"| T021
    ADMIN -->|"set username payload"| T022
    T021 -->|"execSync escape"| RCE
    T022 -->|"eval() escape"| RCE

    classDef risk fill:#dc2626,color:#fff,stroke:#991b1b
```

**Key takeaway:** All five unauthenticated Critical paths (T-001 through T-006, T-018) independently yield admin access; once admin access is achieved, T-021 and T-022 provide OS-level code execution — no privilege boundary exists between authentication bypass and full host compromise.

| ID | Title | Component | Linked Mitigations |
|----|-------|-----------|-------------------|
| [T-001](#t-001) | Hardcoded RSA Private Key | Authentication Service | [M-001](#m-001) · P1 |
| [T-002](#t-002) | SQL Injection in Login | Authentication Service | [M-002](#m-002) · P1 |
| [T-003](#t-003) | JWT Algorithm Confusion | Authentication Service | [M-003](#m-003) · P1 |
| [T-006](#t-006) | SQL Injection in Product Search | REST API (Core Routes) | [M-002](#m-002) · P1 |
| [T-018](#t-018) | XXE in XML File Upload | File Upload Handler | [M-017](#m-017) · P1 |
| [T-021](#t-021) | RCE via B2B Order Sandbox Escape | Admin and Privileged API | [M-020](#m-020) · P1 |
| [T-022](#t-022) | SSTI in User Profile | Admin and Privileged API | [M-020](#m-020) · P1 |

---

## 1. System Overview

OWASP Juice Shop is an intentionally vulnerable web application purpose-built for security training, awareness demonstrations, CTF competitions, and as a test target for DAST/SAST tools. Unlike a production application where the goal is to eliminate vulnerabilities, Juice Shop deliberately implements every OWASP Top Ten category plus dozens of additional security flaws — it is a living, maintained encyclopedia of application security weaknesses.

**Deployment context:** Single-process Node.js (v18+) Express monolith running on port 3000, serving both a REST API and static Angular 17+ SPA assets. SQLite via Sequelize ORM for relational data; an in-process MarsDB instance (MongoDB-compatible) for product reviews. No API gateway, no WAF, no reverse proxy — the Express process is exposed directly to the internet in default deployments.

**Users:** Security trainees, penetration testers, CTF participants, security tool developers, and classroom instructors. The application is also deployed on HerokuApps and as a Docker image for point-in-time training environments.

**Complexity tier: Moderate.** Multiple logical service layers (auth, REST API, file handling, admin, SPA frontend) within a single deployable unit. Container and System Context diagrams are produced; a separate Component diagram is not warranted for this monolith.

**Security impression:** This application is — by design — one of the most comprehensively vulnerable web applications in existence. Every standard STRIDE category is represented with confirmed exploitable code paths. The 7 Critical-risk findings (hardcoded RSA key, SQL injection, JWT algorithm confusion, XXE, RCE via eval, SSTI) are immediately exploitable without authentication in most cases. This threat model documents the full vulnerability surface to serve as a structured reference for training exercises and to demonstrate what a real threat model of an insecure application looks like.

**Context sources:** None (no external context endpoint configured; no business context file found in repository).

**Repo:** [https://github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop)
**Team owner:** OWASP Juice Shop (Bjoern Kimminich)
**Compliance scope:** OWASP Top Ten 2021 (all categories intentionally covered)
**Asset classification:** Tier 2 (intentionally vulnerable training platform)

---

## 2. Architecture Diagrams

The following diagrams model the system architecture at different abstraction levels using the C4 model. Security-relevant components are highlighted with a red border (`:::risk` class) to guide the reader toward the highest-risk areas.

### 2.1 System Context

The Context view shows who interacts with Juice Shop, which external services it depends on, and which trust zones each actor sits in. Red boxes mark components that expose significant attack surface.

```mermaid
graph TD
    subgraph INTERNET["Public Internet — untrusted"]
        USER["Anonymous User\nBrowser / HTTP client"]
        ATTACKER["Attacker\nMalicious HTTP client"]:::risk
        TRAINEE["Security Trainee\nBrowser"]
    end

    subgraph PLATFORM["Deployment Platform"]
        JUICESHOP["OWASP Juice Shop\nNode.js 18 / Express 4\nPort 3000 (HTTP)"]:::risk
    end

    subgraph DATA_TIER["Data Tier — restricted"]
        SQLITE[("SQLite\nUsers, Orders, Products")]:::db
        MARSDB[("MarsDB\nProduct Reviews")]:::db
        FTP["FTP Directory\n/ftp — sensitive files"]:::risk
        ENCKEYS["Encryption Keys\n/encryptionkeys/"]:::risk
    end

    subgraph EXTERNAL["External Services"]
        PROMETHEUS["Prometheus\n/metrics scrape target"]:::risk
    end

    USER -->|"HTTP GET/POST\nport 3000"| JUICESHOP
    ATTACKER -->|"HTTP attacks\nSQLi/XXE/RCE"| JUICESHOP
    TRAINEE -->|"HTTP GET/POST\nport 3000"| JUICESHOP
    JUICESHOP -->|"SQL · TCP (in-process)"| SQLITE
    JUICESHOP -->|"MarsDB API (in-process)"| MARSDB
    JUICESHOP -->|"Serves static files (no auth)"| FTP
    JUICESHOP -->|"Serves key material (no auth)"| ENCKEYS
    JUICESHOP -->|"Exposes metrics (no auth)"| PROMETHEUS

    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff

%% Trust Boundary Key:
%% Public Internet / PLATFORM: no gateway, no WAF — Express exposed directly on :3000
%% Data Tier: in-process SQLite and MarsDB — no network isolation
%% /ftp, /encryptionkeys: served as static files without authentication
```

**Key takeaway:** Every external request — including the attacker — reaches the Express monolith directly on port 3000, with no API gateway and no WAF in front; the entire application surface is the attack surface.

### 2.2 Containers

The Container view zooms into the deployable units within Juice Shop. The critical observation: a single Node.js process handles authentication, authorization, file upload, B2B order evaluation, metrics exposure, and static file serving — a compromise of any one path potentially yields OS-level code execution.

```mermaid
graph TD
    subgraph INTERNET["Public Internet — untrusted"]
        BROWSER["Browser\nAngular 17 SPA\nJWT in localStorage"]:::risk
    end

    subgraph MONOLITH["Express Monolith — port 3000"]
        APIGW["Route Dispatcher\nExpress 4 Router\nserver.ts"]:::risk
        AUTH["Auth Service\nroutes/login.ts\nroutes/changePassword.ts\nlib/insecurity.ts"]:::risk
        RESTAPI["REST API Routes\nroutes/*.ts\nSequelize ORM"]:::risk
        FILEUP["File Upload Handler\nroutes/fileUpload.ts\nlibxmljs2 · yauzl"]:::risk
        B2B["B2B / Admin API\nroutes/b2bOrder.ts\nroutes/userProfile.ts"]:::risk
        STATIC["Static File Server\n/ftp · /encryptionkeys\n/support/logs · /api-docs"]:::risk
    end

    subgraph DATA_TIER["Data Tier — restricted"]
        SQLITE[("SQLite\nvia Sequelize")]:::db
        MARSDB[("MarsDB\nin-process")]:::db
    end

    BROWSER -->|"REST · HTTP (no TLS by default)"| APIGW
    APIGW -->|"JWT validation\nrouting"| AUTH
    APIGW -->|"HTTP routing"| RESTAPI
    APIGW -->|"multipart/form-data"| FILEUP
    APIGW -->|"authenticated POST"| B2B
    APIGW -->|"GET (unauthenticated)"| STATIC
    AUTH -->|"SQL · in-process"| SQLITE
    RESTAPI -->|"SQL · in-process"| SQLITE
    RESTAPI -->|"MarsDB API · in-process"| MARSDB

    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff

%% Trust Boundary Key:
%% INTERNET / MONOLITH: Express handles all inbound; no mutual TLS, no gateway
%% MONOLITH / DATA_TIER: in-process; no separate DB process, no network boundary
%% Static files: served without auth middleware
```

**Key takeaway:** The BFF pattern is absent — the SPA holds JWT tokens in localStorage, so any XSS anywhere on the page can steal the session and achieve full account takeover.

### 2.3 Technology Architecture

This diagram shows the runtime middleware stack from top to bottom. Nodes coloured red carry at least one Medium-or-higher threat from the register.

```mermaid
graph TD
    subgraph BROWSER_LAYER["Browser Layer"]
        SPA["Angular 17 SPA\nTypeScript · RxJS\nBuilt to frontend/dist/"]:::risk
    end

    subgraph EXPRESS_LAYER["Node.js 18 / Express 4"]
        HELMET["helmet 7.x\n(noSniff, frameguard only)\nNo CSP · No HSTS"]:::risk
        CORS["cors() — wildcard\nAll origins permitted"]:::risk
        JWT_MW["express-jwt\nisAuthorized() middleware\nRS256 (but alg:none accepted)"]:::risk
        ROUTES["Route Handlers\nroutes/*.ts — 60+ handlers"]:::risk
        MULTER["multer · file upload\nlibxmljs2 · yauzl"]:::risk
        VM["vm.createContext\nnotevil 1.3.3\nsafeEval (escapable)"]:::risk
    end

    subgraph ORM_LAYER["Data Access"]
        SEQUELIZE["Sequelize 6 ORM\nRaw query fallback — SQLi"]:::risk
        MARSDB_LIB["MarsDB\n(in-process MongoDB-like)"]
    end

    subgraph DATA_LAYER["Persistence"]
        SQLITE_DB[("SQLite 3\nMD5 passwords")]:::risk
        MARSDB_DB[("MarsDB store\nProduct reviews")]:::db
    end

    SPA -->|"HTTP REST · no TLS default"| HELMET
    HELMET -->|"middleware chain"| CORS
    CORS -->|"middleware chain"| JWT_MW
    JWT_MW -->|"route dispatch"| ROUTES
    ROUTES -->|"multipart upload"| MULTER
    ROUTES -->|"B2B eval · SSTI eval"| VM
    ROUTES -->|"ORM + raw query"| SEQUELIZE
    ROUTES -->|"MarsDB API"| MARSDB_LIB
    SEQUELIZE -->|"SQL · in-process"| SQLITE_DB
    MARSDB_LIB -->|"in-process"| MARSDB_DB

    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff

%% Trust Boundary Key:
%% Browser → Transport: No TLS termination proxy; no WAF
%% Middleware → Routes: All roles share same process; no isolation
%% Routes → Data: Raw SQL; in-process SQLite; no DB network boundary
```

**Key takeaway:** The `vm.createContext + notevil` stack provides no real sandboxing — two confirmed RCE paths (B2B safeEval and SSTI eval) bypass it, meaning a single authenticated request can execute arbitrary OS commands on the host.

### 2.4 Security Architecture Assessment

The assessment below evaluates structural patterns rather than individual code defects. Each pattern is rated as present, partial, or absent based on evidence found in the codebase.

#### 2.4.1 Architecture Patterns

The following table evaluates whether standard security architecture patterns are implemented. A well-secured application would show most patterns as present; this application fails on nearly all of them.

| | Pattern | What it means | Finding |
|-|---------|---------------|---------|
| ❌ | Secrets management | Keys and credentials loaded at runtime from a vault, never committed to source. | RSA key, HMAC key, CTF key hardcoded in source — offline token forgery possible. |
| ❌ | Defense-in-depth | Multiple independent security layers prevent a single bypass from leading to full compromise. | Single process — auth bypass, SQLi, and RCE share the same execution context. One exploit = full access. |
| ❌ | Secure defaults | Framework defaults configured to deny by default — strict CORS, disabled XML entities, explicit algorithm allowlists. | cors() wildcard, noent:true in XML parser, alg:none in JWT — every default is insecure. |
| ❌ | Least privilege | Each component runs with minimum permissions; sandboxes enforce process-level isolation. | Express has full filesystem access; vm.createContext sandbox is escapable — two RCE paths. |
| ❌ | API Gateway | Reverse proxy enforces rate limits, TLS termination, and request filtering before traffic reaches application code. | Express exposed directly on :3000 — SQLi and XXE reachable without any pre-filtering. |
| ❌ | BFF (Backend for Frontend) | Backend proxy handles token exchange and stores credentials in httpOnly cookies. | SPA reads JWT from localStorage; any XSS exfiltrates the session token. |
| ❌ | Network segmentation | Databases and internal services isolated on separate networks. | SQLite and MarsDB in-process — no network boundary between app and data tier. |
| ◐ | Separation of concerns | Logic divided into modules with clear boundaries and separate failure domains. | Logical route separation in routes/*.ts, but single Node process; no privilege isolation. |

> ❌ = not implemented · ◐ = partially implemented · ✅ = fully implemented (none in this application)

#### 2.4.2 Key Architectural Risks

These are structural decisions in the architecture that create systemic risk — unlike individual code bugs, they cannot be fixed with a single patch but require architectural changes.

| Risk | Structural Decision | Why it matters | Linked Threats |
|------|---------------------|----------------|----------------|
| 🔴 Critical | JWT private key committed to source repository | Anyone with repo access forges admin tokens offline — no server interaction needed. Renders the entire auth layer void. | [T-001](#t-001), [T-003](#t-003) |
| 🔴 Critical | Sandboxed eval (vm.createContext) inside same process | The sandbox shares the Node.js process with the application. Two confirmed escape paths yield OS-level command execution with no privilege boundary. | [T-021](#t-021), [T-022](#t-022) |
| 🔴 Critical | Single-process monolith with in-process database | No isolation between auth, business logic, and data. Auth bypass gives immediate DB access — credential dump in one step. | [T-002](#t-002), [T-006](#t-006) |
| 🟠 High | Unauthenticated static file exposure (/ftp, /encryptionkeys, /support/logs) | Sensitive directories served without authentication. Encryption keys and log files harvestable by any anonymous visitor. | [T-009](#t-009), [T-023](#t-023) |
| 🟠 High | No network egress filtering on server-side fetch | Server-side requests reach arbitrary destinations including cloud metadata endpoints. Enables SSRF to internal infrastructure. | [T-020](#t-020) |

> 🔴 Critical = architectural root cause of Critical findings; requires structural redesign
> 🟠 High = amplifies attack surface or exposes sensitive data; fixable with configuration changes

#### 2.4.3 Secret Management

- **Current state:** RSA private key hardcoded at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23); HMAC key hardcoded at [lib/insecurity.ts:44](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44); CTF key and premium.key inside `encryptionkeys/` directory served statically.
- **Structural defects:** No vault integration; no environment-variable loading for secrets; pre-commit hooks absent.
- **Impact:** Attacker with read access to the repository or `/encryptionkeys/` endpoint can forge admin JWTs and bypass authentication completely.
- **Target architecture:** Secrets loaded from `process.env` or a mounted Kubernetes secret; `encryptionkeys/` directory removed from static serving.
- **Linked threats:** [T-001](#t-001), [T-003](#t-003)

#### 2.4.4 Authentication

- **Current state:** RS256 JWT issued on login; [lib/insecurity.ts:54-57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) signs tokens; [lib/insecurity.ts:191](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:191) verifies without algorithm enforcement; jsonwebtoken 0.4.0 accepts `alg:none`.
- **Structural defects:** Algorithm enforcement absent; private key in source; token stored in localStorage (XSS extractable); 2FA implemented but bypassable.
- **Impact:** Token forgery without server interaction; full session theft on any XSS.
- **Target architecture:** jsonwebtoken 9.x with `{ algorithms: ['RS256'] }`; private key from env; httpOnly cookie storage.
- **Linked threats:** [T-001](#t-001), [T-003](#t-003), [T-015](#t-015)

```mermaid
graph TD
    subgraph CLIENT["Browser"]
        LOGIN_FORM["Login Form\nPOST /rest/user/login"]
        LS["localStorage\nJWT token (vulnerable)"]:::risk
    end

    subgraph SERVER["Express Monolith"]
        LOGIN_ROUTE["routes/login.ts\nRaw SQL — SQLi possible"]:::risk
        INSECURITY["lib/insecurity.ts\nsign() · RS256 private key HARDCODED"]:::risk
        VERIFY["jwt.verify()\nalg:none accepted"]:::risk
        PROTECTED["Protected Routes\nisAuthorized() middleware"]
    end

    LOGIN_FORM -->|"POST credentials (plain HTTP)"| LOGIN_ROUTE
    LOGIN_ROUTE -->|"if valid — sign JWT"| INSECURITY
    INSECURITY -->|"JWT in response body"| LS
    LS -->|"Authorization: Bearer — all requests"| VERIFY
    VERIFY -->|"decoded user object"| PROTECTED

    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** The authentication chain has three independent critical breaks — SQLi bypasses credential check, alg:none bypasses signature verification, and the hardcoded private key enables offline forgery — any single break yields admin access.

#### 2.4.5 Authorization and Access Control

- **Current state:** `isAuthorized()` express-jwt middleware on most routes; role decoded from JWT payload client-side in Angular guards; `PUT /api/Products/:id` intentionally unprotected ([server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369)); no per-resource ownership check.
- **Structural defects:** RBAC enforcement is JWT-claim-based with no central store; client-side guards provide no server-side protection; IDOR present across basket, recycle, order endpoints.
- **Impact:** Horizontal privilege escalation (access other users' resources); vertical privilege escalation (admin actions without admin role).
- **Target architecture:** Server-side role middleware on every privileged route; ownership predicate on all resource-scoped endpoints.
- **Linked threats:** [T-007](#t-007), [T-013](#t-013), [T-016](#t-016)

#### 2.4.6 Input Validation and Output Encoding

- **Current state:** Sequelize raw query in login and search routes; MarsDB `$where` interpolation in order tracking; `libxmljs2` with `noent: true`; `bypassSecurityTrustHtml` in three Angular components; no global input sanitization middleware.
- **Structural defects:** Validation is per-route rather than centralized; output encoding deliberately bypassed.
- **Impact:** SQL injection, NoSQL injection, XXE, stored XSS — all confirmed exploitable.
- **Linked threats:** [T-002](#t-002), [T-006](#t-006), [T-007](#t-007), [T-008](#t-008), [T-014](#t-014), [T-018](#t-018)

#### 2.4.7 Separation and Isolation

- **Current state:** All application logic runs in a single Node.js process: auth, eval sandbox, file upload, static serving. SQLite and MarsDB are in-process. No process privilege drop; no container namespace separation from host.
- **Structural defects:** vm.createContext is same-process — a sandbox escape yields full process access. No seccomp or AppArmor profile.
- **Impact:** Any RCE path ([T-021](#t-021), [T-022](#t-022)) yields access to all application data and the host filesystem.
- **Linked threats:** [T-021](#t-021), [T-022](#t-022)

#### 2.4.8 Defense-in-Depth

- **Current state:** Helmet provides noSniff and frameguard. Rate limiting on `/rest/user/reset-password` only. Morgan access logging (but logs are world-readable). ZAP DAST scan in CI. No WAF, no IDS, no anomaly detection.
- **Structural defects:** Perimeter defense absent; compensating controls absent; logging tamper-evident only at process level.
- **Linked threats:** [T-010](#t-010), [T-011](#t-011), [T-012](#t-012), [T-017](#t-017)

#### 2.4.9 Overall Architecture Security Rating

🔴 **Critical gaps** — Juice Shop's architecture represents a comprehensive catalogue of absent security controls by design: no network perimeter, in-process secrets, escapable sandbox, missing authorization on key endpoints, and no defense-in-depth layers. Any single critical finding ([T-001](#t-001) through [T-003](#t-003), [T-006](#t-006), [T-018](#t-018), [T-021](#t-021), [T-022](#t-022)) is independently sufficient for full application compromise. This rating reflects the intentional nature of the application and should not be misapplied to production security posture evaluation.

---

## 3. Assets

The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them.

**Classification legend:**
- **Restricted** — highest sensitivity; exposure causes immediate critical impact (keys, payment data)
- **Confidential** — personal or credential data; regulated under GDPR/PCI
- **Internal** — business data not intended for public disclosure
- **Public** — intentionally public; no confidentiality obligation

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|---------------|
| RSA Private Key (JWT signing) | Restricted | RSA private key hardcoded in [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) as PEM string | [T-001](#t-001), [T-003](#t-003) |
| Payment Card Data | Restricted | Payment method records in CardModel | [T-007](#t-007), [T-013](#t-013) |
| Application Configuration and Secrets | Restricted | CTF key, premium.key, jwt.pub in encryptionkeys/ — all world-readable | [T-001](#t-001), [T-009](#t-009) |
| User Credentials (email + MD5 password hash) | Confidential | All user account credentials stored in SQLite. Passwords hashed with MD5 (broken algorithm) | [T-002](#t-002), [T-005](#t-005), [T-006](#t-006) |
| JWT Authentication Tokens | Confidential | RS256-signed JWTs stored in client localStorage. 6-hour expiry, no revocation | [T-003](#t-003), [T-015](#t-015) |
| Customer Personal Data (PII) | Confidential | Names, addresses, payment card data, profile images. GDPR-relevant | [T-007](#t-007), [T-009](#t-009) |
| Security Q&A Answers | Confidential | HMAC-SHA256 hashed security answers. HMAC key hardcoded | [T-005](#t-005) |
| Customer Order History | Internal | Purchase orders stored in MarsDB. Linked to obfuscated email | [T-007](#t-007), [T-008](#t-008) |
| Application Access Logs | Internal | Morgan combined-format logs served unauthenticated at /support/logs | [T-009](#t-009), [T-010](#t-010) |
| Prometheus Metrics | Internal | Business intelligence data served at /metrics without auth | [T-023](#t-023) |
| FTP Directory Contents | Internal | Sensitive files served unauthenticated at /ftp including acquisitions.md and incident-support.kdbx | [T-009](#t-009) |
| Product Catalog | Public | Product descriptions, images, prices. Publicly readable | [T-013](#t-013) |

---

## 4. Attack Surface

All identified entry points through which an attacker can interact with the system, split by whether authentication is required.

### 4.1 Unauthenticated Entry Points (11)

These endpoints accept requests from any client without requiring a valid JWT token. They represent the broadest attack surface and the highest priority for hardening.

| Entry Point | Protocol | Notes | Linked Threats |
|-------------|----------|-------|---------------|
| POST /rest/user/login | HTTP | SQL injection via email/password fields | [T-002](#t-002) |
| GET /rest/products/search | HTTP | UNION-based SQL injection via q parameter | [T-006](#t-006) |
| POST /file-upload | HTTP | XXE via XML upload, ZIP path traversal, YAML bomb | [T-018](#t-018), [T-019](#t-019), [T-011](#t-011) |
| GET /metrics | HTTP | Prometheus metrics — no authentication | [T-009](#t-009), [T-023](#t-023) |
| GET /ftp | HTTP | Sensitive files served without auth | [T-009](#t-009) |
| GET /encryptionkeys | HTTP | JWT public key and premium.key | [T-001](#t-001), [T-009](#t-009) |
| GET /support/logs | HTTP | Application access logs exposed | [T-009](#t-009), [T-010](#t-010) |
| GET /api-docs | HTTP | Full Swagger API documentation | [T-009](#t-009) |
| GET /rest/track-order/:id | HTTP | NoSQL injection and reflected XSS | [T-008](#t-008) |
| GET /redirect | HTTP | Open redirect | [T-016](#t-016) |
| POST /api/Users | HTTP | User registration — no rate limit | [T-013](#t-013) |

### 4.2 Authenticated Entry Points (5)

These endpoints require a valid JWT token. However, several contain vulnerabilities that allow authenticated attackers to exceed their intended privilege level.

| Entry Point | Protocol | Notes | Linked Threats |
|-------------|----------|-------|---------------|
| POST /b2b/v2/orders | HTTP | RCE via notevil/vm2 sandbox escape | [T-021](#t-021) |
| POST /profile/image/url | HTTP | SSRF via arbitrary URL fetch | [T-020](#t-020) |
| GET /rest/user/change-password | HTTP | Password change without requiring current password | [T-004](#t-004) |
| PATCH /rest/products/reviews | HTTP | NoSQL injection via _id | [T-008](#t-008) |
| GET /profile | HTTP | SSTI via username and CSP injection | [T-022](#t-022) |

---

## 5. Trust Boundaries

Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk.

The overall trust model is extremely flat: a single Express process handles all requests without a gateway or WAF, and all trust decisions are made at the application layer with no network-level enforcement.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|-------------|---------------|
| 1 | Public Internet to Express Monolith | Anonymous attacker / user | Express route handlers | None — port 3000 directly exposed | No rate limiting, no IP allowlist, no WAF | [T-002](#t-002), [T-006](#t-006), [T-009](#t-009), [T-011](#t-011), [T-018](#t-018) |
| 2 | JWT Authentication Boundary | Unauthenticated request | Protected route handlers | `isAuthorized()` express-jwt middleware ([server.ts:355-451](vscode://file/home/mrohr/juice-shop/server.ts:355)) | Algorithm not enforced; private key hardcoded; token in localStorage | [T-001](#t-001), [T-003](#t-003), [T-015](#t-015) |
| 3 | Role-Based Access Boundary | Authenticated user | Admin / privileged operations | JWT role claim decoded inline; Angular guards client-side | No central RBAC; client-side guards bypassable; IDOR on resource endpoints | [T-007](#t-007), [T-013](#t-013), [T-016](#t-016), [T-021](#t-021) |
| 4 | Frontend to Backend API | Angular SPA | Express REST API | CORS header (wildcard); same JWT token | CORS wildcard; JWT in localStorage extractable by XSS | [T-014](#t-014), [T-015](#t-015), [T-017](#t-017) |

**Note on Boundary 1:** The absence of a reverse proxy means brute-force attacks, YAML bombs, and XML uploads with malicious payloads all reach the application without any pre-processing filter. Introducing Nginx or a WAF would provide immediate layered protection.

**Note on Boundary 3:** The role check is performed by decoding the JWT claim inline in each handler rather than via a shared middleware. This means any handler that omits the role check — intentional or accidental — creates a privilege escalation vector without any structural safety net.

---

## 6. Identified Security Controls

The following controls were identified in the codebase. Their effectiveness is rated against the actual protection they provide.

**Gap summary:** The five most critical control gaps are: (1) no Content-Security-Policy header globally, enabling XSS escalation; (2) no HTTPS/TLS enforcement, exposing JWT tokens and credentials in transit; (3) CORS wildcard allows any origin to make credentialed cross-site requests; (4) MD5 password hashing provides near-zero protection against credential cracking; and (5) JWT algorithm enforcement absent, allowing the `alg:none` forgery attack despite RS256 being used for signing.

Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|---------------|
| IAM | JWT Authentication (RS256) | [lib/insecurity.ts:54-57](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:54) | 🔶 Weak | [T-001](#t-001), [T-003](#t-003) |
| IAM | 2FA via TOTP | [routes/2fa.ts](vscode://file/home/mrohr/juice-shop/routes/2fa.ts) | ⚠️ Partial | [T-003](#t-003) |
| Authorization | express-jwt isAuthorized middleware | [server.ts:355-451](vscode://file/home/mrohr/juice-shop/server.ts:355) | ⚠️ Partial | [T-007](#t-007), [T-013](#t-013), [T-016](#t-016) |
| Data Protection | MD5 password hashing | [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) | 🔶 Weak | [T-005](#t-005) |
| Data Protection | HMAC-SHA256 security answer hashing | [lib/insecurity.ts:44](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:44) | 🔶 Weak | [T-005](#t-005) |
| Input Validation | Rate limiting on /rest/user/reset-password | [server.ts:343-352](vscode://file/home/mrohr/juice-shop/server.ts:343) | ⚠️ Partial | [T-011](#t-011) |
| Audit & Logging | Morgan combined access logging | [server.ts:338](vscode://file/home/mrohr/juice-shop/server.ts:338) | ⚠️ Partial | [T-010](#t-010) |
| Infrastructure | Helmet (noSniff, frameguard) | [server.ts:185-186](vscode://file/home/mrohr/juice-shop/server.ts:185) | ⚠️ Partial | [T-017](#t-017) |
| Infrastructure | CSP header | missing | ❌ Missing | [T-014](#t-014), [T-017](#t-017) |
| Infrastructure | HTTPS/TLS enforcement | missing | ❌ Missing | [T-015](#t-015) |
| Infrastructure | CORS restriction | [server.ts:181-182](vscode://file/home/mrohr/juice-shop/server.ts:181) (wildcard) | 🔶 Weak | [T-013](#t-013), [T-014](#t-014) |
| Security Testing | ZAP DAST scan (CI) | [.github/workflows/zap_scan.yml](vscode://file/home/mrohr/juice-shop/.github/workflows/zap_scan.yml) | ⚠️ Partial | — |
| Dependency | CycloneDX SBOM generation | [Dockerfile](vscode://file/home/mrohr/juice-shop/Dockerfile) | ⚠️ Partial | — |

---

## 7. Threat Register

This register documents all identified threats using the STRIDE methodology. Risk is derived from likelihood × impact. All 24 threats are from the initial full assessment (v1, 2026-04-12).

**Risk methodology:** Likelihood (High/Medium/Low) × Impact (Critical/High/Medium/Low) → Risk (Critical/High/Medium/Low). Critical risk requires High likelihood + Critical impact, or confirmed exploit with no mitigating control.

**Risk Distribution:**

| Severity | Count | Percentage |
|----------|-------|-----------|
| Critical | 7 | 29% |
| High | 12 | 50% |
| Medium | 5 | 21% |
| Low | 0 | 0% |

**STRIDE Coverage:**

| Category | Count |
|----------|-------|
| Spoofing | 3 |
| Tampering | 7 |
| Repudiation | 2 |
| Information Disclosure | 6 |
| Denial of Service | 1 |
| Elevation of Privilege | 5 |

**Risk Distribution:** Critical: 7 · High: 12 · Medium: 5 · Low: 0 · **Total: 24**
**STRIDE Coverage:** Spoofing: 3 · Tampering: 7 · Repudiation: 2 · Information Disclosure: 6 · Denial of Service: 1 · Elevation of Privilege: 5

### 7.1 Critical (7)

The seven Critical-risk threats represent immediately exploitable vulnerabilities — most are unauthenticated and can be chained to achieve full application compromise.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|------------------|-------------|
| <a id="t-001"></a>T-001 | Authentication Service | Tampering | RSA private key is hardcoded in [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) as a PEM string in source code. Any attacker with repository read access can extract this key and forge administrator JWT tokens offline with no detection. (CWE-321) | High | Critical | 🔴 Critical | JWT signed with RS256; public key used for verification | [M-001](#m-001) |
| <a id="t-002"></a>T-002 | Authentication Service | Tampering | Login route at [routes/login.ts:36](vscode://file/home/mrohr/juice-shop/routes/login.ts:36) constructs SQL query via raw string interpolation. An unauthenticated attacker submitting `email=' OR 1=1--` bypasses authentication and gains admin access. (CWE-89) | High | Critical | 🔴 Critical | None — raw string interpolation directly in sequelize.query() | [M-002](#m-002) |
| <a id="t-003"></a>T-003 | Authentication Service | Spoofing | jsonwebtoken v0.4.0 does not enforce algorithm on verification. An attacker can craft a JWT with algorithm 'none' that is accepted by jwt.verify() at [lib/insecurity.ts:191](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:191). (CWE-347) | High | Critical | 🔴 Critical | RS256 enforced on signing; verification does not enforce algorithm | [M-003](#m-003) |
| <a id="t-006"></a>T-006 | REST API (Core Routes) | Tampering | Product search at [routes/search.ts:22](vscode://file/home/mrohr/juice-shop/routes/search.ts:22) injects the user-supplied q parameter directly into a raw SQL query. Attacker can perform UNION SELECT to dump the entire Users table including password hashes and emails. (CWE-89) | High | Critical | 🔴 Critical | Query length limited to 200 chars; no parameterization | [M-002](#m-002) |
| <a id="t-018"></a>T-018 | File Upload Handler | Information Disclosure | XML upload in [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) uses libxmljs2.parseXml() with noent: true, enabling XXE. Attacker reads arbitrary local files (e.g., /etc/passwd) via crafted DOCTYPE with SYSTEM entity. Parsed content returned in error message. (CWE-611) | High | Critical | 🔴 Critical | Runs in vm.createContext sandbox; noent: true explicitly enables entity resolution | [M-017](#m-017) |
| <a id="t-021"></a>T-021 | Admin and Privileged API | Elevation of Privilege | B2B order endpoint POST /b2b/v2/orders ([routes/b2bOrder.ts:21-23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:21)) evaluates orderLinesData using notevil v1.3.3 within vm.createContext. Known sandbox escape vectors via prototype pollution allow authenticated B2B attacker to achieve RCE. (CWE-94) | Medium | Critical | 🔴 Critical | vm.createContext sandbox with 2000ms timeout; notevil safe-eval wrapper | [M-020](#m-020) |
| <a id="t-022"></a>T-022 | Admin and Privileged API | Elevation of Privilege | SSTI in [routes/userProfile.ts:57](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:57) evaluates username content matching `/#{(.*)}/` using Node.js eval() inside pug template rendering. Authenticated attacker sets username to `#{process.mainModule.require('child_process').execSync('id')}` to achieve RCE. (CWE-94) | Medium | Critical | 🔴 Critical | Regex match required; eval() called only when pattern matches | [M-020](#m-020) |

### 7.2 High (12)

High-risk threats are exploitable but may require authentication or have limited blast radius compared to Critical findings.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|------------------|-------------|
| <a id="t-004"></a>T-004 | Authentication Service | Tampering | Password change endpoint GET /rest/user/change-password does not require currentPassword when omitted. Authenticated attacker can change any user's password without knowing the current one. (CWE-620) | Medium | High | 🟠 High | Requires valid JWT token; current password checked only if provided | [M-004](#m-004) |
| <a id="t-005"></a>T-005 | Authentication Service | Information Disclosure | Password hashing uses MD5 ([lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43)). MD5 is cryptographically broken; extracted password hashes can be cracked using rainbow tables or GPU brute force in minutes. HMAC key hardcoded at line 44. (CWE-916) | High | High | 🟠 High | Passwords are hashed; HMAC applied to security answers | [M-005](#m-005) |
| <a id="t-007"></a>T-007 | REST API (Core Routes) | Tampering | Systemic IDOR — missing ownership checks across authenticated resource endpoints: BasketItem update ([routes/basketItems.ts:68](vscode://file/home/mrohr/juice-shop/routes/basketItems.ts:68)) finds item by id only; RecycleItem ([routes/recycles.ts:14](vscode://file/home/mrohr/juice-shop/routes/recycles.ts:14)) queries by id with no ownership; Order delivery toggle ([routes/orderHistory.ts:36](vscode://file/home/mrohr/juice-shop/routes/orderHistory.ts:36)) updates by _id with no ownership. (CWE-639) | High | High | 🟠 High | isAuthorized() confirms valid JWT; no per-resource ownership check | [M-006](#m-006) |
| <a id="t-008"></a>T-008 | REST API (Core Routes) | Tampering | NoSQL injection: [routes/updateProductReviews.ts](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts) passes req.body.id unsanitized as `{ _id: req.body.id }` to MarsDB with `{ multi: true }`. Track order at [routes/trackOrder.ts](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts) uses `$where` with string interpolation. (CWE-943) | High | Medium | 🟠 High | isAuthorized() on PATCH; track order is unauthenticated | [M-007](#m-007) |
| <a id="t-009"></a>T-009 | REST API (Core Routes) | Information Disclosure | Unauthenticated management endpoints: GET /metrics at [server.ts:718](vscode://file/home/mrohr/juice-shop/server.ts:718) exposes Prometheus data; GET /ftp serves sensitive files (acquisitions.md, incident-support.kdbx); GET /support/logs exposes access logs; GET /rest/admin/application-configuration returns full app config. (CWE-200) | High | High | 🟠 High | robots.txt disallows /ftp; no authentication enforced | [M-008](#m-008) |
| <a id="t-011"></a>T-011 | REST API (Core Routes) | Denial of Service | YAML bomb via file upload ([routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) handleYamlUpload): attacker uploads a YAML file with nested anchor/alias expansion causing exponential memory growth, crashing the Node.js process. Only a 2-second VM timeout. (CWE-400) | Medium | High | 🟠 High | VM timeout set to 2000ms; file type check present | [M-010](#m-010) |
| <a id="t-013"></a>T-013 | REST API (Core Routes) | Elevation of Privilege | PUT /api/Products/:id is commented out of isAuthorized() protection at [server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369). Product price and description can be modified by unauthenticated requests. CORS wildcard ([server.ts:182](vscode://file/home/mrohr/juice-shop/server.ts:182)) allows cross-site requests from any origin. (CWE-306) | High | High | 🟠 High | Most endpoints protected; PUT /api/Products/:id intentionally unprotected | [M-012](#m-012) |
| <a id="t-014"></a>T-014 | Angular SPA Frontend | Tampering | bypassSecurityTrustHtml used without sanitization in: [about.component.ts:119](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119) (user feedback); [last-login-ip.component.ts:39](vscode://file/home/mrohr/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.ts:39) (lastLoginIp field); [administration.component.ts:60,78](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60) (user email and feedback). Stored XSS payloads execute in admin and about views. (CWE-79) | High | High | 🟠 High | Angular DomSanitizer present but explicitly bypassed | [M-013](#m-013) |
| <a id="t-015"></a>T-015 | Angular SPA Frontend | Information Disclosure | JWT tokens stored in localStorage ([frontend/src/app/Services/request.interceptor.ts:13](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13)). Any XSS payload can read localStorage and exfiltrate the token enabling full account takeover. (CWE-922) | High | High | 🟠 High | No httpOnly cookie fallback | [M-014](#m-014) |
| <a id="t-016"></a>T-016 | Angular SPA Frontend | Spoofing | AdminGuard and AccountingGuard perform role checks client-side by decoding JWT payload. Direct URL navigation bypasses Angular route guards. Server API does not enforce admin role on all admin-accessible data endpoints. (CWE-602) | Medium | High | 🟠 High | Angular route guards present; server enforces isAuthorized() but not admin role everywhere | [M-015](#m-015) |
| <a id="t-019"></a>T-019 | File Upload Handler | Tampering | ZIP file upload handler ([routes/fileUpload.ts:38-48](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:38)) uses String.includes() on path.resolve() to check for path traversal. This check can be bypassed with crafted paths allowing writes outside uploads/complaints/. (CWE-22) | Medium | High | 🟠 High | absolutePath.includes(path.resolve('.')) check present but bypassable | [M-018](#m-018) |
| <a id="t-020"></a>T-020 | File Upload Handler | Spoofing | Profile image URL upload ([routes/profileImageUrlUpload.ts:24](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:24)) fetches any attacker-controlled URL server-side. Attacker causes server to request internal services (AWS metadata 169.254.169.254, localhost). Only a path-based regex exclusion. (CWE-918) | High | High | 🟠 High | Minimal path-based regex check; no allowlist of permitted domains/IPs | [M-019](#m-019) |

### 7.3 Medium (5)

Medium-risk threats have limited impact or require specific conditions that reduce their exploitability relative to High findings.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|------------------|-------------|
| <a id="t-010"></a>T-010 | REST API (Core Routes) | Repudiation | Access logs served unauthenticated at /support/logs. An attacker can eliminate evidence of their attack by deleting log files. No log integrity mechanism or remote forwarding. (CWE-778) | Medium | Medium | 🟡 Medium | Morgan logs to rotating file; errorhandler active | [M-009](#m-009) |
| <a id="t-012"></a>T-012 | REST API (Core Routes) | Information Disclosure | errorhandler middleware ([server.ts:676](vscode://file/home/mrohr/juice-shop/server.ts:676)) active in all environments without NODE_ENV check. Full stack traces including file paths and internal state returned to the client on unhandled errors. (CWE-209) | High | Medium | 🟡 Medium | errorhandler NPM package applied; no environment gating | [M-011](#m-011) |
| <a id="t-017"></a>T-017 | Angular SPA Frontend | Information Disclosure | No Content-Security-Policy header is set globally. The userProfile route CSP ([routes/userProfile.ts:88](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88)) includes 'unsafe-eval'. No HSTS configured. Full absence of defensive headers enables XSS escalation. (CWE-693) | High | Medium | 🟡 Medium | Helmet noSniff and frameguard only | [M-016](#m-016) |
| <a id="t-023"></a>T-023 | Admin and Privileged API | Information Disclosure | Prometheus metrics endpoint GET /metrics ([server.ts:718](vscode://file/home/mrohr/juice-shop/server.ts:718)) is registered outside the Express middleware chain with no authentication. Exposes user counts, wallet balances, challenge solve statistics. (CWE-200) | High | Medium | 🟡 Medium | None | [M-008](#m-008) |
| <a id="t-024"></a>T-024 | Admin and Privileged API | Repudiation | GET /rest/user/authentication-details returns all active JWT tokens and session data to any authenticated user. Attacker with valid JWT can enumerate all active sessions for user impersonation. No audit trail for admin actions. (CWE-778) | Medium | Medium | 🟡 Medium | isAuthorized() required; no per-session audit log | [M-009](#m-009) |

### 7.4 Low (0)

No Low-risk threats were identified. All findings are Medium or above.

---

## 8. Attack Walkthroughs

The sequence diagrams below trace each Critical finding from initial attacker action to full exploitation. Every diagram is anchored to its T-NNN in the Threat Register and shows the current vulnerable behaviour alongside the post-mitigation flow.

### 8.1 — [T-001](#t-001) Hardcoded RSA Key — Offline JWT Forgery

Unauthenticated attacker, Authentication Service component. This walkthrough shows how a hardcoded RSA private key in source code enables offline admin JWT forgery without any server interaction.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant GH as GitHub Repository
    participant SIGN as jwt.sign() (offline)
    participant API as Juice Shop API

    ATK->>GH: GET raw lib/insecurity.ts
    GH-->>ATK: 200 OK — PEM private key exposed in source
    ATK->>SIGN: jwt.sign({email:'admin@juice-sh.op', role:'admin'}, privateKey, {algorithm:'RS256'})
    SIGN-->>ATK: forged admin JWT token
    ATK->>API: GET /rest/user/authentication-details (Authorization: Bearer forged-token)
    API-->>ATK: 200 OK — all active sessions returned
    Note over ATK,API: Full admin access achieved with zero server interaction
```

**Key takeaway:** The attacker never authenticates — the private key in source code makes the JWT signing ceremony entirely bypassable offline.

### 8.2 — [T-002](#t-002) SQL Injection in Login — Authentication Bypass

Unauthenticated attacker, Authentication Service component. This walkthrough shows how a single crafted email parameter bypasses authentication and yields an admin session.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant LOGIN as POST /rest/user/login
    participant DB as SQLite (sequelize.query)

    ATK->>LOGIN: POST {email: "' OR 1=1--", password: "x"}
    LOGIN->>DB: SELECT * FROM Users WHERE email='' OR 1=1--' AND password='...'
    Note over DB: 1=1 evaluates true — all rows returned
    DB-->>LOGIN: First row (admin user)
    LOGIN-->>ATK: 200 OK — JWT token for admin account
    ATK->>LOGIN: All subsequent requests with admin JWT
    Note over ATK,DB: No valid credentials required
```

**Key takeaway:** The raw SQL string interpolation at [routes/login.ts:36](vscode://file/home/mrohr/juice-shop/routes/login.ts:36) makes authentication entirely bypassable with a single request.

### 8.3 — [T-003](#t-003) JWT Algorithm Confusion — Token Forgery

Unauthenticated attacker, Authentication Service component. This walkthrough shows how jsonwebtoken 0.4.0's missing algorithm enforcement allows a crafted `alg:none` token to be accepted.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant CRAFT as JWT Craft (local)
    participant VERIFY as jwt.verify() (lib/insecurity.ts:191)
    participant API as Protected Route

    ATK->>CRAFT: Encode header {alg:'none'} + payload {email:'admin',role:'admin'} + empty sig
    CRAFT-->>ATK: eyJ... (alg:none JWT)
    ATK->>VERIFY: jwt.verify(token, publicKey, callback) — no algorithm restriction
    Note over VERIFY: jsonwebtoken 0.4.0 accepts alg:none without signature check
    VERIFY-->>ATK: decoded payload — accepted as valid
    ATK->>API: Request with forged token
    API-->>ATK: 200 OK — admin access granted
```

**Key takeaway:** Without `{ algorithms: ['RS256'] }` passed to jwt.verify(), the RS256 public key provides zero protection — any client can create a self-signed-nothing token.

### 8.4 — [T-018](#t-018) XXE in XML File Upload — Local File Read

Unauthenticated attacker, File Upload Handler component. This walkthrough shows how the `noent: true` option in the XML parser enables arbitrary local file disclosure.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant UPLOAD as POST /file-upload
    participant PARSER as libxmljs2.parseXml()
    participant FS as Host Filesystem

    ATK->>UPLOAD: POST multipart — XML file with DOCTYPE SYSTEM entity
    Note over ATK: <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
    UPLOAD->>PARSER: parseXml(data, {noent: true})
    PARSER->>FS: Read /etc/passwd (entity resolution enabled)
    FS-->>PARSER: File contents
    PARSER-->>UPLOAD: Parsed XML with entity expanded
    UPLOAD-->>ATK: Error response containing /etc/passwd contents
    Note over ATK,FS: Arbitrary local file read achieved unauthenticated
```

**Key takeaway:** A single-line fix (`noent: false`) closes this vector entirely — the `noent: true` option serves no legitimate purpose in this context.

### 8.5 — [T-021](#t-021) RCE via B2B Order Sandbox Escape

Authenticated B2B customer, Admin and Privileged API component. This walkthrough shows how a crafted `orderLinesData` payload escapes the `notevil` sandbox and executes OS commands.

```mermaid
sequenceDiagram
    participant ATK as Attacker (authenticated)
    participant B2B as POST /b2b/v2/orders
    participant VM as vm.createContext sandbox
    participant OS as OS (child_process)

    ATK->>B2B: POST {orderLinesData: "require('child_process').execSync('id').toString()"}
    B2B->>VM: vm.runInContext('safeEval(orderLinesData)', sandbox, {timeout:2000})
    Note over VM: notevil 1.3.3 — prototype pollution escape path
    VM->>OS: execSync('id')
    OS-->>VM: uid=1000(node) ...
    VM-->>B2B: RCE output in response
    B2B-->>ATK: 200 OK — command output returned
    Note over ATK,OS: Full OS access from authenticated HTTP request
```

**Key takeaway:** The `vm.createContext + notevil` combination provides no real sandboxing — structured JSON schema validation of order lines would eliminate the eval surface entirely.

---

## 9. Mitigation Register

Prioritised measures to address identified threats. Each mitigation lists the threats it addresses, the requirements it fulfils, the rollout priority (P1–P4) and concrete implementation guidance.

### P1 — Immediate

These mitigations address Critical-risk threats with Low effort. They should be implemented in the current sprint regardless of other priorities.

---

#### <a id="m-001"></a>M-001 — Externalize RSA Private Key to Environment Variable or Secret Manager

**Addresses:** [T-001](#t-001)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** The RSA private key hardcoded at [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23) allows any repo reader to forge admin JWTs offline. This is the single highest-risk finding.

**How:**
1. Remove the hardcoded PEM string from [lib/insecurity.ts:23](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:23)
2. Load the private key from `process.env.JWT_PRIVATE_KEY` or a mounted secret file
3. Rotate the RSA keypair immediately after deployment
4. Add a pre-commit hook (git-secrets or truffleHog) to prevent future key commits

```typescript
// Before: const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXA...'
// After: const privateKey = process.env.JWT_PRIVATE_KEY || fs.readFileSync('/run/secrets/jwt_private_key', 'utf8')
```

**Verification:** Confirm key is absent from git history (`git log -S 'BEGIN RSA PRIVATE KEY'`). Verify JWT signing still works after rotation.

---

#### <a id="m-002"></a>M-002 — Replace Raw SQL String Interpolation with Parameterized Queries

**Addresses:** [T-002](#t-002), [T-006](#t-006)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** Raw SQL interpolation at [routes/login.ts:36](vscode://file/home/mrohr/juice-shop/routes/login.ts:36) and [routes/search.ts:22](vscode://file/home/mrohr/juice-shop/routes/search.ts:22) enables unauthenticated admin bypass and full database dump.

**How:**
1. Replace raw `sequelize.query()` with Sequelize ORM `findOne`/`findAll` with where clauses
2. In [routes/login.ts:36](vscode://file/home/mrohr/juice-shop/routes/login.ts:36), use `UserModel.findOne({ where: { email, password } })`
3. In [routes/search.ts:22](vscode://file/home/mrohr/juice-shop/routes/search.ts:22), use `Sequelize Op.like` with parameterized input

```typescript
// Before: models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
// After: UserModel.findOne({ where: { email: req.body.email, password: security.hash(req.body.password) } })
```

**Verification:** Send `email=' OR 1=1--` to POST /rest/user/login; server must respond 401.

---

#### <a id="m-003"></a>M-003 — Upgrade jsonwebtoken and Enforce Algorithm on Verification

**Addresses:** [T-003](#t-003)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** jsonwebtoken 0.4.0 accepts `alg:none` tokens at [lib/insecurity.ts:191](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:191), making the entire signing infrastructure bypassable.

**How:**
1. Upgrade jsonwebtoken from 0.4.0 to 9.x
2. Pass `{ algorithms: ['RS256'] }` as options to `jwt.verify()` in [lib/insecurity.ts:191](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:191)
3. Audit all `jwt.verify()` call sites

```typescript
// Before: jwt.verify(token, publicKey, callback)
// After: jwt.verify(token, publicKey, { algorithms: ['RS256'] }, callback)
```

**Verification:** Craft a JWT with `alg:none` header; server must return 401.

---

#### <a id="m-008"></a>M-008 — Add Authentication to Management and Debug Endpoints

**Addresses:** [T-009](#t-009), [T-023](#t-023)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** GET /metrics, /ftp, /support/logs, and /encryptionkeys are all reachable without authentication, exposing Prometheus data, sensitive documents, and key material.

**How:**
1. Move GET /metrics behind `isAuthorized()` or a dedicated metrics auth token
2. Restrict `/ftp`, `/support/logs`, `/encryptionkeys` to admin role
3. Remove sensitive files from `ftp/` in production (acquisitions.md, incident-support.kdbx)

```typescript
// Before: app.get('/metrics', metrics.serveMetrics())
// After: app.get('/metrics', security.isAuthorized(), metrics.serveMetrics())
```

**Verification:** Request GET /metrics without Authorization header; server must respond 401.

---

#### <a id="m-012"></a>M-012 — Restore Auth Middleware on PUT /api/Products/:id and Restrict CORS

**Addresses:** [T-013](#t-013)
**Priority:** **P1 — Immediate**
**Severity:** 🟠 High
**Effort:** Low

**Why:** The commented-out auth middleware at [server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369) allows unauthenticated product modification. CORS wildcard enables cross-site exploitation.

**How:**
1. Uncomment [server.ts:369](vscode://file/home/mrohr/juice-shop/server.ts:369): `app.put('/api/Products/:id', security.isAuthorized())`
2. Replace `cors()` wildcard with restricted origin list
3. Add CSRF protection for state-changing endpoints

```typescript
// Before: // app.put('/api/Products/:id', security.isAuthorized())
// After: app.put('/api/Products/:id', security.isAuthorized())
```

**Verification:** Send PUT /api/Products/1 without Authorization header; server must respond 401.

---

#### <a id="m-017"></a>M-017 — Disable External Entity Processing in XML Parser (XXE Fix)

**Addresses:** [T-018](#t-018)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Low

**Why:** `noent: true` in libxmljs2 at [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) enables XXE arbitrary file read — a one-option fix closes the vector.

**How:**
1. Change `libxmljs2.parseXml()` options from `{ noent: true }` to `{ noent: false }`
2. If XML parsing not needed in production, remove the XML upload handler
3. Validate file content type header in addition to extension check

```typescript
// Before: libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })
// After: libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })
```

**Verification:** Upload XML with XXE payload; response must not contain /etc/passwd content.

---

#### <a id="m-020"></a>M-020 — Remove eval-based Code Execution from B2B Orders and User Profile

**Addresses:** [T-021](#t-021), [T-022](#t-022)
**Priority:** **P1 — Immediate**
**Severity:** 🔴 Critical
**Effort:** Medium

**Why:** Two independent RCE paths via eval: B2B orders at [routes/b2bOrder.ts:21-23](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:21) and SSTI at [routes/userProfile.ts:57](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:57). Both must be eliminated.

**How:**
1. In [routes/b2bOrder.ts](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts), replace `safeEval`/`vm.runInContext` with structured JSON schema validation
2. In [routes/userProfile.ts:57](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:57), remove `eval(code)` block; treat username as display text only
3. If expression evaluation is required, restrict to a DSL with no code execution

```typescript
// Before: vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
// After: const orderLines = JSON.parse(orderLinesData); if (!Array.isArray(orderLines)) throw new Error('Invalid format')
```

**Verification:** POST to /b2b/v2/orders with `orderLinesData: 'process.exit(1)'`; server must remain alive and return 400.

---

### P2 — This Sprint

These mitigations address High-risk threats. They should be scheduled for implementation in the current or next sprint.

---

#### <a id="m-004"></a>M-004 — Require Current Password for Password Change

**Addresses:** [T-004](#t-004)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Password change without current password verification at [routes/changePassword.ts](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts) allows any authenticated attacker to take over any account.

**How:**
1. In [routes/changePassword.ts](vscode://file/home/mrohr/juice-shop/routes/changePassword.ts), make `currentPassword` a required parameter
2. Return 400 if `currentPassword` is absent or empty
3. Always verify `hash(currentPassword) === loggedInUser.data.password`

```typescript
// Before: if (currentPassword && security.hash(currentPassword) !== ...)
// After: if (!currentPassword) return res.status(401).send('Current password is required.')
```

**Verification:** Send password change with no current password; server must respond 401.

---

#### <a id="m-005"></a>M-005 — Replace MD5 Password Hashing with bcrypt

**Addresses:** [T-005](#t-005)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** MD5 hashing at [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) provides near-zero protection — hashes are crackable in seconds with modern hardware.

**How:**
1. Replace `crypto.createHash('md5')` in [lib/insecurity.ts:43](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) with `bcrypt.hash(data, 12)`
2. Update `UserModel` to store bcrypt hashes
3. On login, use `bcrypt.compare()` instead of hash equality
4. Move HMAC key from hardcoded string to environment variable

```typescript
// Before: export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
// After: export const hash = async (data: string) => bcrypt.hash(data, 12)
```

**Verification:** New registrations must produce hashes starting with `$2b$`; MD5 hashes must not be accepted.

---

#### <a id="m-006"></a>M-006 — Add Ownership Checks to All Resource-Scoped Endpoints

**Addresses:** [T-007](#t-007)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Systemic IDOR across basket items, recycle items, and order history allows any authenticated user to read or modify another user's data.

**How:**
1. In [routes/basketItems.ts](vscode://file/home/mrohr/juice-shop/routes/basketItems.ts), verify `item.BasketId === authenticatedUser.bid`
2. In [routes/recycles.ts](vscode://file/home/mrohr/juice-shop/routes/recycles.ts), add `WHERE UserId = authenticatedUser.id`
3. In [routes/orderHistory.ts](vscode://file/home/mrohr/juice-shop/routes/orderHistory.ts), verify ownership before update

```typescript
// Before: BasketItemModel.findOne({ where: { id: req.params.id } })
// After: BasketItemModel.findOne({ where: { id: req.params.id, BasketId: user.bid } })
```

**Verification:** Attempt to update a basket item belonging to another user; server must respond 403.

---

#### <a id="m-007"></a>M-007 — Sanitize NoSQL Query Parameters and Disable dollar-where

**Addresses:** [T-008](#t-008)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Unsanitized MarsDB query parameters at [routes/updateProductReviews.ts](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts) and [routes/trackOrder.ts](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts) allow NoSQL injection.

**How:**
1. In [routes/updateProductReviews.ts](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts), validate `req.body.id` is a valid ObjectId string
2. Remove `{ multi: true }` unless bulk update is required
3. In [routes/trackOrder.ts](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts), replace `$where` interpolation with exact equality match

```typescript
// Before: db.ordersCollection.find({ $where: `this.orderId === '${id}'` })
// After: db.ordersCollection.find({ orderId: id })
```

**Verification:** Send `{'$gt':''}` as review id; server must reject with 400 or return no results.

---

#### <a id="m-010"></a>M-010 — Restrict File Upload Types and Add Upload Rate Limiting

**Addresses:** [T-011](#t-011)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** YAML bomb uploads at [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts) can crash the Node.js process, causing complete service unavailability.

**How:**
1. Reject YAML/YML uploads in production if not needed
2. Apply per-user rate limiting on `/file-upload` endpoint (max 5 uploads/min)
3. Set maximum upload size at reverse proxy level

**Verification:** Upload a YAML bomb; server should reject or enforce timeout without crashing.

---

#### <a id="m-011"></a>M-011 — Disable errorhandler in Production and Sanitize Error Responses

**Addresses:** [T-012](#t-012)
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** Stack traces returned at [server.ts:676](vscode://file/home/mrohr/juice-shop/server.ts:676) expose internal file paths and state, aiding attacker reconnaissance.

**How:**
1. Wrap errorhandler with `NODE_ENV` check: `if (process.env.NODE_ENV !== 'production') app.use(errorhandler())`
2. Add production error handler returning generic messages without stack traces

```typescript
// After: if (process.env.NODE_ENV !== 'production') { app.use(errorhandler()) } else { app.use((err,req,res,next) => { logger.error(err.stack); res.status(500).json({error:'Internal server error'}) }) }
```

**Verification:** Trigger a 500 error in production mode; response must not contain stack trace.

---

#### <a id="m-013"></a>M-013 — Remove bypassSecurityTrustHtml Calls and Use Angular Sanitizer

**Addresses:** [T-014](#t-014)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Three Angular components explicitly bypass XSS protection, enabling stored XSS in admin and user-visible views.

**How:**
1. In [about.component.ts:119](vscode://file/home/mrohr/juice-shop/frontend/src/app/about/about.component.ts:119), replace `bypassSecurityTrustHtml` with `DomSanitizer.sanitize(SecurityContext.HTML, ...)`
2. In [last-login-ip.component.ts:39](vscode://file/home/mrohr/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.ts:39), use text binding instead of `innerHTML`
3. In [administration.component.ts:60,78](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60), use Angular default text interpolation

```typescript
// Before: this.sanitizer.bypassSecurityTrustHtml(comment)
// After: this.sanitizer.sanitize(SecurityContext.HTML, comment)
```

**Verification:** Post feedback containing `<script>alert(1)</script>`; script must not execute.

---

#### <a id="m-015"></a>M-015 — Enforce Server-Side Role Checks for Admin Data Endpoints

**Addresses:** [T-016](#t-016)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Medium

**Why:** Client-side Angular guards provide no server-side protection; admin data endpoints are accessible to any authenticated user.

**How:**
1. Add `isAdmin()` check to `GET /rest/user/authentication-details`
2. Add admin role check to all endpoints consumed by `AdministrationComponent`
3. Remove reliance on Angular route guards as sole authorization mechanism

**Verification:** Send `GET /rest/user/authentication-details` with non-admin JWT; server must respond 403.

---

#### <a id="m-016"></a>M-016 — Implement Content-Security-Policy and Security Headers

**Addresses:** [T-017](#t-017)
**Priority:** **P2 — This Sprint**
**Severity:** 🟡 Medium
**Effort:** Low

**Why:** Absent CSP and HSTS at application level enable XSS escalation and man-in-the-middle attacks.

**How:**
1. Add `helmet.contentSecurityPolicy()` with restrictive policy: `default-src 'self'; script-src 'self'; object-src 'none'`
2. Add HSTS: `helmet.hsts({ maxAge: 31536000, includeSubDomains: true })`
3. Remove `'unsafe-eval'` from per-page CSP in [routes/userProfile.ts:88](vscode://file/home/mrohr/juice-shop/routes/userProfile.ts:88)

```typescript
app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], objectSrc: ["'none'"] } }))
```

**Verification:** Check response headers; `Content-Security-Policy` and `Strict-Transport-Security` must be present.

---

#### <a id="m-018"></a>M-018 — Fix ZIP Path Traversal with Safe Extraction

**Addresses:** [T-019](#t-019)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** String.includes() path check at [routes/fileUpload.ts:38-48](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:38) is bypassable with crafted ZIP entry paths.

**How:**
1. Replace `String.includes()` path check with `path.normalize()` and `startsWith()` verification
2. Use `path.basename(fileName)` to strip directory components from entry paths
3. Reject any entry whose normalized path escapes the target directory

```typescript
// Before: if (absolutePath.includes(path.resolve('.')))
// After: const safePath = path.normalize(path.join(targetDir, path.basename(fileName))); if (!safePath.startsWith(targetDir + path.sep)) { entry.autodrain(); return }
```

**Verification:** Upload ZIP with entry path `../../ftp/legal.md`; file must not appear in ftp/ directory.

---

#### <a id="m-019"></a>M-019 — Add SSRF Protection to Profile Image URL Fetch

**Addresses:** [T-020](#t-020)
**Priority:** **P2 — This Sprint**
**Severity:** 🟠 High
**Effort:** Low

**Why:** Server-side URL fetch at [routes/profileImageUrlUpload.ts:24](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:24) with no IP allowlist enables SSRF to internal services.

**How:**
1. Validate URL against an allowlist of permitted schemes (https only)
2. Block requests to RFC-1918 private IP ranges and 169.254.x
3. Set a 3-second timeout and 1MB max response size on fetch

```typescript
// After validation: const blockedRanges = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)/; const { address } = await dns.promises.lookup(parsedUrl.hostname); if (blockedRanges.test(address)) throw new Error('Internal URL blocked')
```

**Verification:** Set profile image URL to `http://169.254.169.254/latest/meta-data/`; server must reject.

---

### P3 — Next Quarter

These mitigations address residual risks or require significant architectural change.

---

#### <a id="m-009"></a>M-009 — Restrict Log Access and Implement Centralized Audit Logging

**Addresses:** [T-010](#t-010), [T-024](#t-024)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟡 Medium
**Effort:** Medium

**Why:** World-readable logs at /support/logs allow evidence tampering; no audit trail for admin actions enables repudiation.

**How:**
1. Remove `/support/logs` route or restrict to admin role
2. Forward logs to a remote SIEM or centralized logging system
3. Implement structured audit log entries for authentication events and admin actions

**Verification:** Request `GET /support/logs` without admin JWT; server must respond 401 or 404.

---

#### <a id="m-014"></a>M-014 — Move JWT Token from localStorage to httpOnly Cookie

**Addresses:** [T-015](#t-015)
**Priority:** **P3 — Next Quarter**
**Severity:** 🟠 High
**Effort:** High

**Why:** JWT in localStorage at [frontend/src/app/Services/request.interceptor.ts:13](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts:13) is extractable by any XSS payload, enabling account takeover.

**How:**
1. Change `POST /rest/user/login` to set token as `httpOnly, Secure, SameSite=Strict` cookie
2. Remove token from JSON response body and localStorage in [request.interceptor.ts](vscode://file/home/mrohr/juice-shop/frontend/src/app/Services/request.interceptor.ts)
3. Add CSRF token header check for state-changing requests

**Verification:** After login, token must not be accessible via `document.cookie` or `localStorage`.

---

### P4 — Backlog

No mitigations are currently assigned to the backlog tier. All identified mitigations are P1–P3 due to the severity profile of this application.

---

## 10. Out of Scope

The following areas were not analyzed as part of this assessment:

- **Infrastructure-level controls** (Docker host hardening, Kubernetes network policies, cloud IAM) — deployment environment is not part of the repository
- **Third-party service security** (Heroku, Docker Hub) — external hosting providers
- **Physical security and operational procedures** — not applicable to a training application
- **Compliance auditing** — Juice Shop is a training platform, not a compliance-scoped production application
- **Frontend JavaScript supply chain** (npm package security for Angular dependencies) — SCA scan was not enabled for this run (`WITH_SCA=false`)
- **Transitive dependency vulnerabilities** — would require SCA scan (`--with-sca` flag)
- **CI/CD pipeline security** — GitHub Actions workflow hardening was not included in STRIDE analysis for this run (MAX_STRIDE_COMPONENTS=5, pipeline did not fit within cap)
- **Mobile or native clients** — no mobile application present in repository
- **API versioning security** (v1 vs v2 endpoints) — covered at the route level in REST API component analysis
