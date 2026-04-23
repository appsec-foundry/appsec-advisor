# Threat Model — OWASP Juice Shop

> | | |
> |---|---|
> | **Project** | OWASP Juice Shop v19.2.1 |
> | **Description** | Intentionally vulnerable web application for security training, CTF competitions, and penetration testing exercises |
> | **Author** | Bjoern Kimminich (bjoern.kimminich@owasp.org) |
> | **License** | MIT |
> | **Repository** | https://github.com/juice-shop/juice-shop |
> | **Homepage** | https://owasp.org/www-project-juice-shop/ |
> | **Runtime** | `Node.js` 24, Express 4.22, Angular 20, SQLite 3 / MarsDB, `Socket.IO` 3 |
> | **Tags** | security-training, ctf, owasp, intentionally-vulnerable, nodejs, angular |

---

## Changelog

| Version | Date | Mode | Components Re-analyzed | Threats | Note |
|--------- |------ |------ |------------------------ |--------- |------ |
| v3 | 2026-04-18 | Full (resumed) | 8 | 47 | Resumed from Phase 9 merge — all 8 STRIDE analyzers completed; merged and finalized |
| v2 | 2026-04-17 | Full | 8 | 55 | Forced full re-assessment (--full flag); prior changelog v1 preserved |
| v1 | 2026-04-15 | Full | 8 | 51 | Initial assessment |

---

## Table of Contents

1. [Management Summary](#management-summary)
2. [System Overview](#1-system-overview)
3. [Architecture Diagrams](#2-architecture-diagrams)
   - [2.1 System Context](#21-system-context)
   - [2.2 Container Architecture](#22-container-architecture)
   - [2.3 Components](#23-components)
   - [2.4 Technology Architecture](#24-technology-architecture)
4. [Attack Walkthroughs](#3-attack-walkthroughs)
   - [3.1 Attack Chain Overview](#31-attack-chain-overview)
   - [3.2 Offline JWT Forgery via Hardcoded RSA Key](#32-offline-jwt-forgery-via-hardcoded-rsa-key)
   - [3.3 SQL Injection Login Bypass](#33-sql-injection-login-bypass)
   - [3.4 RCE via notevil Sandbox Escape](#34-rce-via-notevil-sandbox-escape)
   - [3.5 SQL Injection in Product Search](#35-sql-injection-in-product-search)
5. [Assets](#4-assets)
6. [Attack Surface](#5-attack-surface)
   - [5.1 Unauthenticated Entry Points](#51-unauthenticated-entry-points-12)
   - [5.2 Authenticated Entry Points](#52-authenticated-entry-points-5)
7. [Security Architecture](#7-security-architecture)
   - [7.1 Overview](#71-overview)
   - [7.2 Key Architectural Risks](#72-key-architectural-risks)
   - [7.3 Identity & Access Management](#73-identity--access-management)
   - [7.4 Authorization](#74-authorization)
   - [7.5 Input Validation & Output Encoding](#75-input-validation--output-encoding)
   - [7.6 Data Protection & Session Management](#76-data-protection--session-management)
   - [7.7 Frontend Security](#77-frontend-security)
   - [7.8 Real-time / WebSocket](#78-real-time--websocket)
   - [7.9 AI / LLM](#79-ai--llm)
   - [7.10 Audit & Logging](#710-audit--logging)
   - [7.11 Infrastructure & Network Segmentation](#711-infrastructure--network-segmentation)
   - [7.12 Dependency & Supply Chain](#712-dependency--supply-chain)
   - [7.13 Secret Management](#713-secret-management)
   - [7.14 Defense-in-Depth Assessment](#714-defense-in-depth-assessment)
8. [Threat Register](#8-threat-register)
   - [8.A Categories at a glance](#8a-categories-at-a-glance)
   - [8.B Critical Categories (6)](#8b-critical-categories-6)
   - [8.B High Categories (9)](#8b-high-categories-9)
   - [8.B Medium Categories (1)](#8b-medium-categories-1)
   - [8.C Compound Attack Chains](#8c-compound-attack-chains)
   - [8.D Architectural Findings](#8d-architectural-findings)
9. [Mitigation Register](#9-mitigation-register)
   - [P1 — Immediate](#p1--immediate)
   - [P2 — This Sprint](#p2--this-sprint)
   - [P3 — Next Quarter](#p3--next-quarter)
   - [P4 — Backlog](#p4--backlog)
10. [Out of Scope](#10-out-of-scope)
11. [Appendix: Run Statistics](#appendix-run-statistics)
12. [Appendix A — Vektor Taxonomy](#appendix-a-vektor-taxonomy)

---

## Management Summary

### Verdict

🔴 **CRITICAL SECURITY POSTURE** — OWASP Juice Shop has severe, exploitable vulnerabilities across every layer of the stack. This is expected for a deliberate training platform, but the patterns closely mirror real-world production failures. The assessment identified **10 Critical** and **25 High** findings.

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

- **Full database theft without login** — A SQL Injection (SQLi) flaw in the product search lets any internet user extract the entire customer table, including email addresses and password hashes, in a single web request. *([F-009](#f-009))*
- **Admin login without a password** — A similar SQL Injection flaw in the login endpoint allows an attacker to log in as any user — including administrators — without knowing the password. *([F-014](#f-014))*
- **Server takeover from a normal user account** — Any logged-in user can send a crafted B2B order to run arbitrary commands on the server (Remote Code Execution, RCE), giving full control over the application host. *([F-010](#f-010))*
- **Admin impersonation via a leaked source-code secret** — The RSA private key used to sign session tokens (JSON Web Tokens, JWT) is committed to the public GitHub repository. An attacker downloads the key and issues valid admin tokens offline. *([F-001](#f-001), [F-005](#f-005))*
- **Hijacking every active user via Cross-Site Scripting** — Session tokens are stored in browser local storage with no Content Security Policy (CSP). A Cross-Site Scripting (XSS) payload placed on any shared page steals the session of every customer who visits it. *([F-008](#f-008), [F-024](#f-024))*

</blockquote>

The combination of these attack chains means an internet attacker can achieve full database compromise and server-level code execution with no rate limiting or anomaly detection in the path.

### Security Posture at a Glance

#### Threat Heatmap — Architecture View

```mermaid
flowchart TB
    ATK(["🎯 &nbsp;<b>INTERNET ATTACKER</b>&nbsp;<br/><i>unauthenticated</i>"]):::attacker

    subgraph EDGE["🌐 &nbsp;EDGE &nbsp;—&nbsp; no WAF · no rate limits"]
        direction LR
        C01["<b>C-01</b><br/>REST API<br/>🔴 <b>4 Critical</b>"]:::crit
        C08["<b>C-08</b><br/>Angular SPA<br/>🟠 <b>2 High</b>"]:::high
    end

    subgraph SRV["⚙️ &nbsp;MONOLITH &nbsp;—&nbsp; single Node.js process · no sandbox"]
        direction LR
        C02["<b>C-02</b><br/>Auth Service<br/>🔴 <b>3 Critical</b>"]:::crit
        C04["<b>C-04</b><br/>B2B Orders<br/>🔴 <b>1 Critical</b>"]:::crit
        C05["<b>C-05</b><br/>File Upload<br/>🔴 <b>3 Critical</b>"]:::crit
        C06["<b>C-06</b><br/>Chatbot<br/>🔴 <b>1 Critical</b>"]:::crit
        COTH["<b>C-03 · C-07</b><br/>Admin · Reviews<br/>🟠 Low-Impact"]:::muted
    end

    subgraph DATA["💾 &nbsp;DATA &nbsp;—&nbsp; in-process · no network separation"]
        direction LR
        DB[("<b>SQLite</b><br/>Users · Orders")]:::data
        FS["<b>/ftp · /logs · /keys</b><br/>🔴 publicly readable"]:::crit
    end

    ATK ===>|" ① &nbsp;<b>F-009</b> &nbsp; SQLi → Users dump "| C01
    ATK ===>|" ② &nbsp;<b>F-014</b> &nbsp; SQLi login bypass "| C01
    ATK ===>|" ③ &nbsp;<b>F-010</b> &nbsp; B2B payload → RCE "| C04
    ATK ===>|" ④ &nbsp;<b>F-006/007</b> &nbsp; XXE · ZIP Slip "| C05
    ATK -.->|" ⑤ &nbsp;<b>F-001</b> &nbsp; RSA key from public Git "| C02

    C01 --> DB
    C05 --> FS
    C08 -.->|"JWT in localStorage"| C01

    click C01 "#c-01" "C-01 REST API"
    click C02 "#c-02" "C-02 Auth Service"
    click C04 "#c-04" "C-04 B2B Orders"
    click C05 "#c-05" "C-05 File Upload"
    click C06 "#c-06" "C-06 Chatbot"
    click C08 "#c-08" "C-08 Frontend SPA"

    classDef attacker fill:#0f172a,stroke:#000,color:#fff,stroke-width:3px,font-size:16px
    classDef crit fill:#fca5a5,stroke:#991b1b,color:#111,stroke-width:3px,font-size:14px
    classDef high fill:#fdba74,stroke:#9a3412,color:#111,stroke-width:2px,font-size:14px
    classDef muted fill:#e5e7eb,stroke:#9ca3af,color:#6b7280,stroke-dasharray:4,font-size:12px
    classDef data fill:#86efac,stroke:#166534,color:#111,stroke-width:2px,font-size:14px

    linkStyle 0,1,2,3 stroke:#b91c1c,stroke-width:4px
    linkStyle 4 stroke:#b91c1c,stroke-width:3px,stroke-dasharray:8
```

Where the Critical findings concentrate in the architecture. Component boxes link to [§2.3 Components](#23-components); numbered arrows ①–⑤ map 1:1 to the finding IDs in [§8.B Critical Categories](#8b-critical-categories-6).

#### Crown Jewels & Attack Paths — Asset View

```mermaid
graph LR
    subgraph ATTACKERS["🎯 Attacker Positions"]
        A1(["Internet<br/>Anonymous"]):::attacker
        A2(["Internet<br/>Auth User"]):::attacker
        A3(["Repo-Read<br/>(public GitHub)"]):::attacker
    end

    subgraph JEWELS["💎 Crown Jewels"]
        J1["<b>User Credentials</b><br/>email + password hash"]:::jewel
        J2["<b>JWT Signing Key</b><br/>RSA private"]:::jewel
        J3["<b>Admin Rights</b><br/>role claim"]:::jewel
        J4["<b>Server Process</b><br/>code execution"]:::jewel
        J5["<b>Customer Session</b><br/>active JWTs"]:::jewel
    end

    A1 ==>|"<b>F-009</b> SQLi"| J1
    A1 ==>|"<b>F-014</b> SQLi login"| J3
    A1 ==>|"<b>F-011</b> mass assign"| J3
    A3 ==>|"<b>F-001</b> key in Git"| J2
    J2 -.->|"offline forge"| J3
    A2 ==>|"<b>F-010</b> notevil RCE"| J4
    J4 -.->|"pivot"| J1
    A1 ==>|"<b>F-024</b> stored XSS"| J5
    J5 -.->|"account takeover"| J3

    classDef attacker fill:#0f172a,stroke:#000,color:#fff,stroke-width:2px,font-size:14px
    classDef jewel fill:#fde68a,stroke:#b45309,color:#111,stroke-width:2px,font-size:14px
    linkStyle 0,1,2,3,5,7 stroke:#b91c1c,stroke-width:3px
    linkStyle 4,6,8 stroke:#6b7280,stroke-width:1px,stroke-dasharray:4
```

Which assets are directly at stake. Solid red arrows are single-step exploits; dashed grey arrows are *pivots* covered in detail by [§8.C Compound Attack Chains](#8c-compound-attack-chains). Assets are defined in [§4 Assets](#4-assets).

### Top Findings

The **20 highest-risk items** across code, configuration and architecture, sorted by impact-weighted score. F-IDs jump to full finding detail in [§8.B](#8b-critical-categories); AF-IDs jump to [§8.D](#8d-architectural-findings).

| # | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations |
|--- |------------- |--------- |----------- |-------- |-------- |--------------------- |
| 1 | 🔴 Critical | [F-009](#f-009) — SQL Injection in product search | [C-01](#c-01) — REST API | [TH-01](#th-01) — Injection | [Internet Anon](#vektor-internet-anon) | [M-007](#m-007) — Parameterize all raw SQL queries (P1) |
| 2 | 🔴 Critical | [F-007](#f-007) — Path Traversal (ZIP Slip) in `routes/fileUpload.ts` | [C-05](#c-05) — File Upload | [TH-07](#th-07) — Insecure File Handling | [Internet User](#vektor-internet-user) | [M-005](#m-005) — Disable XXE and validate ZIP entry paths (P1) |
| 3 | 🔴 Critical | [F-014](#f-014) — SQL Injection in login | [C-01](#c-01) — REST API | [TH-01](#th-01) — Injection | [Internet Anon](#vektor-internet-anon) | [M-007](#m-007) — Parameterize all raw SQL queries (P1) |
| 4 | 🔴 Critical | [F-010](#f-010) — Remote Code Execution via `notevil` sandbox escape | [C-04](#c-04) — B2B Orders | [TH-05](#th-05) — Code Execution | [Internet User](#vektor-internet-user) | [M-008](#m-008) — Replace notevil with static expression parser (P1) |
| 5 | 🔴 Critical | [F-011](#f-011) — Mass Assignment in user registration | [C-01](#c-01) — REST API | [TH-06](#th-06) — Broken Access Control | [Internet Anon](#vektor-internet-anon) | [M-009](#m-009) — Add field allowlist to User.create() (P1) |
| 6 | 🔴 Critical | [F-006](#f-006) — XML External Entity (XXE) injection in `routes/fileUpload.ts` | [C-05](#c-05) — File Upload | [TH-07](#th-07) — Insecure File Handling | [Internet User](#vektor-internet-user) | [M-005](#m-005) — Disable XXE and validate ZIP entry paths (P1) |
| 7 | 🔴 Critical | [F-051](#f-051) — Server-Side Request Forgery + LLM training-data poisoning via chatbot `trainingData` URL | [C-06](#c-06) — Chatbot | [TH-08](#th-08) — SSRF | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data (P2) |
| 8 | 🔴 Critical | [F-027](#f-027) — Server-Side Request Forgery (SSRF) via profile image URL | [C-01](#c-01) — REST API | [TH-08](#th-08) — SSRF | [Internet User](#vektor-internet-user) | [M-019](#m-019) — Add URL allowlist for profile image fetch (P2) |
| 9 | 🔴 Critical | [F-049](#f-049) — Missing Authentication on `Socket.IO` WebSocket upgrade | [C-01](#c-01) — REST API | [TH-09](#th-09) — Unauth. Mgmt Plane | [Internet Anon](#vektor-internet-anon) | [M-027](#m-027) — Authenticate `Socket.IO` WS upgrade and validate Origin (P2) |
| 10 | 🟠 High | [F-024](#f-024) — Stored/Reflected XSS via `DomSanitizer` bypass | [C-08](#c-08) — Frontend SPA | [TH-11](#th-11) — XSS | [Victim-Required](#vektor-victim-required) | [M-017](#m-017) — Remove DomSanitizer bypasses and innerHTML assignments (P2) |
| 11 | 🟠 High | [F-025](#f-025) — DOM-based XSS via `innerHTML` in Angular | [C-08](#c-08) — Frontend SPA | [TH-11](#th-11) — XSS | [Victim-Required](#vektor-victim-required) | [M-017](#m-017) — Remove DomSanitizer bypasses and innerHTML assignments (P2) |
| 12 | 🟠 High | [F-017](#f-017) — Cross-Site Request Forgery on password change | [C-01](#c-01) — REST API | [TH-15](#th-15) — CSRF | [Victim-Required](#vektor-victim-required) | [M-013](#m-013) — Add CSRF protection to state-changing endpoints (P2) |
| 13 | 🟠 High | [AF-007](#af-007) — No supply-chain integrity controls in build pipeline | Architecture | [TH-14](#th-14) — Supply-Chain | [n/a](#vektor-n-a) | [M-028](#m-028) — Pin container base images and lock down training data (P2) |
| 14 | 🟠 High | [F-028](#f-028) — Unrestricted file upload (dangerous file types) | [C-05](#c-05) — File Upload | [TH-07](#th-07) — Insecure File Handling | [Internet User](#vektor-internet-user) | [M-005](#m-005) — Disable XXE and validate ZIP entry paths (P1) |
| 15 | 🟠 High | [F-016](#f-016) — Two-Factor Authentication (TOTP) bypass | [C-02](#c-02) — Auth Service | [TH-02](#th-02) — Broken Authentication | [Internet User](#vektor-internet-user) | [M-012](#m-012) — Enforce 2FA across all authentication paths (P2) |
| 16 | 🟠 High | [F-004](#f-004) — JSON Web Token signature bypass (`alg:none` accepted) | [C-02](#c-02) — Auth Service | [TH-02](#th-02) — Broken Authentication | [Internet Anon](#vektor-internet-anon) | [M-003](#m-003) — Pin JWT algorithm to RS256 (P1) |
| 17 | 🟠 High | [F-005](#f-005) — JSON Web Token signed with hardcoded key → admin impersonation | [C-02](#c-02) — Auth Service | [TH-06](#th-06) — Broken Access Control | [Internet User](#vektor-internet-user) | [M-001](#m-001) — Rotate all hardcoded secrets (P1)<br/>[M-004](#m-004) — Enforce server-side admin role on all admin endpoints (P1) |
| 18 | 🟠 High | [F-001](#f-001) — Hardcoded RSA private key in `lib/insecurity.ts` | [C-02](#c-02) — Auth Service | [TH-03](#th-03) — Cryptographic Failures | [Repo-Read](#vektor-repo-read) | [M-001](#m-001) — Rotate all hardcoded secrets (P1) |
| 19 | 🟠 High | [AF-002](#af-002) — All secrets embedded in source code | [C-02](#c-02) — Auth Service | [TH-03](#th-03) — Cryptographic Failures | [n/a](#vektor-n-a) | [M-001](#m-001) — Rotate all hardcoded secrets (P1) |
| 20 | 🟠 High | [AF-003](#af-003) — Unsafe user input reaches eval-equivalent code execution | [C-04](#c-04) — B2B Orders | [TH-05](#th-05) — Code Execution | [n/a](#vektor-n-a) | [M-008](#m-008) — Replace notevil with static expression parser (P1) |

_+28 additional ≥High findings — see [Section 8.B](#8b-critical-categories) and [Section 8.D](#8d-architectural-findings)._

_Legend: 🔴 Critical (directly exploitable, major impact) · 🟠 High · 🟡 Medium · 🟢 Low. **Vektor** values link to full definitions in [Appendix A — Vektor Taxonomy](#appendix-a-vektor-taxonomy)._

### Architecture Assessment

🔴 **Verdict — the architecture has no effective security boundary at any layer.** Eight of eight core security patterns (API Gateway/WAF, Defense-in-Depth, Separation of Concerns, Least Privilege, Secrets Management, Network Segmentation, Secure Defaults, BFF/Proxy) are **absent or only partially implemented**. A single successful attack against any Critical finding yields full system compromise — no compensating control at a secondary layer would slow an attacker down.

Four cross-cutting defects drive ~40% of all findings:

| Defect | Description | Key Findings |
|-------- |------------- |-------------- |
| **Secrets in source code** | RSA private key, HMAC secret, and cookie secret are committed to a public repository — every authentication control ([§7.3](#73-identity--access-management)) is undermined from the moment the repo is cloned | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts<br/>[F-005](#f-005) — JWT signed with hardcoded key — admin impersonation<br/>[F-033](#f-033) — Hardcoded HMAC coupon key |
| **Injection everywhere** | Five distinct injection classes reachable from HTTP input: SQLi, NoSQLi, XXE, XSS (via DomSanitizer bypass), and RCE via notevil + vm. No central input validator | [F-009](#f-009) — SQL injection in product search<br/>[F-014](#f-014) — SQL injection in login<br/>[F-010](#f-010) — RCE via notevil sandbox escape<br/>[F-006](#f-006) — XXE via libxml2 with noent:true<br/>[F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()<br/>[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular |
| **Unauthenticated management plane** | `/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics`, and the `Socket.IO` WebSocket upgrade are all reachable without any authentication | [F-012](#f-012) — Unauthenticated /ftp directory listing<br/>[F-032](#f-032) — Application logs served unauthenticated<br/>[F-034](#f-034) — Prometheus /metrics unauthenticated<br/>[F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade |
| **Browser-resident session material** | JWT and user PII stored in localStorage with no CSP — any XSS escalates to full account takeover | [F-008](#f-008) — JWT stored in localStorage<br/>[F-040](#f-040) — Sensitive data in localStorage<br/>[F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml() |

See **[§7 Security Architecture](#7-security-architecture)** for the full per-domain assessment (14 subsections), the control catalog (39 controls), cross-cutting treatments of Secret Management and Defense-in-Depth, and the overall rating.

### Mitigations

#### Prioritized Mitigations

The mitigations below address Critical and High severity findings with active exploitation potential and should be completed before the next release. Entries are ordered by effort (lowest first), then by number of threats addressed (highest first).

| ID | Mitigation | Component | Addresses | Effort |
|---- |------------ |----------- |----------- |-------- |
| [M-001](#m-001) | Rotate all hardcoded secrets | [C-02](#c-02) Auth Service | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts<br/>[F-005](#f-005) — JWT signed with hardcoded key — admin impersonation<br/>[F-033](#f-033) — Hardcoded HMAC coupon key | Low |
| [M-003](#m-003) | Pin JWT algorithm to RS256 | [C-02](#c-02) Auth Service | [F-004](#f-004) — JWT alg:none bypass | Low |
| [M-004](#m-004) | Enforce server-side admin role on all admin endpoints | [C-01](#c-01) REST API<br/>[C-03](#c-03) Admin Panel | [F-005](#f-005) — JWT signed with hardcoded key — admin impersonation<br/>[F-013](#f-013) — Full user list accessible to any authenticated user<br/>[F-023](#f-023) — Admin panel client-side guard only<br/>[F-046](#f-046) — Admin user deletion without safeguards | Low |
| [M-005](#m-005) | Disable XXE and validate ZIP entry paths | [C-05](#c-05) File Upload | [F-006](#f-006) — XXE via libxml2 with noent:true<br/>[F-007](#f-007) — ZIP Slip path traversal in routes/fileUpload.ts<br/>[F-028](#f-028) — Unrestricted file type upload | Low |
| [M-007](#m-007) | Parameterize all raw SQL queries | [C-01](#c-01) REST API | [F-009](#f-009) — SQL injection in product search<br/>[F-014](#f-014) — SQL injection in login | Low |
| [M-009](#m-009) | Add field allowlist to User.create() | [C-01](#c-01) REST API | [F-011](#f-011) — Mass assignment in user registration<br/>[F-047](#f-047) — Stack traces exposed in error responses | Low |
| [M-002](#m-002) | Replace MD5 with bcrypt | [C-02](#c-02) Auth Service | [F-002](#f-002) — Password hashing uses MD5 without salt<br/>[F-022](#f-022) — OAuth predictable password derived as MD5(email) | Medium |
| [M-008](#m-008) | Replace notevil with static expression parser | [C-04](#c-04) B2B Orders | [F-010](#f-010) — RCE via notevil sandbox escape<br/>[F-029](#f-029) — CPU exhaustion DoS via complex expression<br/>[F-044](#f-044) — B2B orders not audited | High |
| [M-006](#m-006) | Move JWT from localStorage to HttpOnly cookie | [C-08](#c-08) Frontend SPA<br/>[C-02](#c-02) Auth Service | [F-008](#f-008) — JWT stored in localStorage<br/>[F-040](#f-040) — Sensitive data in localStorage | Medium |

#### Follow-up Mitigations

The mitigations below address the remaining Medium and Low severity findings and should be scheduled within the current development sprint. Entries are ordered by effort (lowest first), then by number of threats addressed (highest first).

| ID | Mitigation | Component | Addresses | Effort |
|---- |------------ |----------- |----------- |-------- |
| [M-010](#m-010) | Restrict /ftp and log endpoints | [C-01](#c-01) REST API | [F-012](#f-012) — Unauthenticated /ftp directory listing<br/>[F-032](#f-032) — Application logs served unauthenticated | Low |
| [M-011](#m-011) | Replace security questions with email OTP | [C-02](#c-02) Auth Service | [F-015](#f-015) — Password reset via guessable security answers | Medium |
| [M-013](#m-013) | Add CSRF protection to state-changing endpoints | [C-01](#c-01) REST API | [F-017](#f-017) — CSRF on password change | Low |
| [M-014](#m-014) | Add ownership check to basket and order routes | [C-01](#c-01) REST API | [F-018](#f-018) — IDOR on basket and order endpoints | Low |
| [M-015](#m-015) | Fix NoSQL injection and add author binding in reviews | [C-07](#c-07) Product Reviews | [F-019](#f-019) — NoSQL injection via $where in reviews<br/>[F-020](#f-020) — Mass update IDOR in reviews<br/>[F-041](#f-041) — Reviews not bound to verified identity | Low |
| [M-016](#m-016) | Migrate OAuth to PKCE authorization code flow | [C-02](#c-02) Auth Service<br/>[C-08](#c-08) Frontend SPA | [F-021](#f-021) — OAuth implicit flow used in frontend<br/>[F-045](#f-045) — OAuth implicit flow token in URL fragment | Medium |
| [M-017](#m-017) | Remove DomSanitizer bypasses and innerHTML assignments | [C-08](#c-08) Frontend SPA | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()<br/>[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular | Medium |
| [M-018](#m-018) | Disable YAML entity expansion in file upload | [C-05](#c-05) File Upload | [F-026](#f-026) — YAML bomb (billion laughs) in file upload | Low |
| [M-019](#m-019) | Add URL allowlist for profile image fetch | [C-01](#c-01) REST API | [F-027](#f-027) — SSRF via profile image URL | Low |
| [M-020](#m-020) | Add admin role check and audit logging to chatbot | [C-06](#c-06) Chatbot | [F-030](#f-030) — Chatbot admin functions without role check<br/>[F-042](#f-042) — User data leakage via username injection<br/>[F-043](#f-043) — Chatbot interactions not logged | Medium |
| [M-021](#m-021) | Restrict CORS to allowed origins | [C-01](#c-01) REST API | [F-031](#f-031) — CORS wildcard Access-Control-Allow-Origin: * | Low |
| [M-022](#m-022) | Restrict /metrics to internal networks | [C-01](#c-01) REST API | [F-034](#f-034) — Prometheus /metrics unauthenticated | Low |
| [M-027](#m-027) | Authenticate `Socket.IO` WS upgrade and validate Origin | [C-01](#c-01) REST API | [F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade | Medium |
| [M-028](#m-028) | Pin container base images and lock down training data | [C-06](#c-06) Chatbot | [F-050](#f-050) — Supply-chain / container hygiene<br/>[F-051](#f-051) — Chatbot trainingData URL fetched without validation | Medium |

### Operational Strengths

Despite the structurally deficient design, the project implements several security-relevant controls. None fully mitigate Critical findings, but each reduces part of the attack surface. This table is a filtered view of [Section 7](#7-security-architecture) — rows with effectiveness ≥ Weak and `show_in_strengths_by_default: true`. The full catalog, including ❌ Missing controls, lives in Section 7.

| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |
|----------------------- |---------------- |--------------- |----- |----------- |
| Role-Based Access Control | isAccounting() / isDeluxe() / isAdmin() role checks on a subset of routes | ⚠️ Partial | ensureAdminRole missing on /api/Users, chatbot admin actions, B2B order ingestion; Admin panel guard is client-side Angular route guard only | [F-010](#f-010) — RCE via notevil sandbox escape<br/>[F-013](#f-013) — Full user list accessible to any authenticated user<br/>[F-023](#f-023) — Admin panel client-side guard only<br/>[F-030](#f-030) — Chatbot admin functions without role check<br/>[F-046](#f-046) — Admin user deletion without safeguards |
| Explicit Deny Baseline | denyAll() middleware applied to challenge-related routes | ⚠️ Partial | Not applied to /api/Users, /ftp, /support/logs, /metrics | [F-013](#f-013) — Full user list accessible to any authenticated user<br/>[F-023](#f-023) — Admin panel client-side guard only<br/>[F-030](#f-030) — Chatbot admin functions without role check |
| HTTP Security Headers | helmet middleware — X-Content-Type-Options, X-Frame-Options | ⚠️ Partial | CSP absent; HSTS absent; Permissions-Policy absent | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()<br/>[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular<br/>[F-039](#f-039) — Missing Content Security Policy |
| Parameterized Database Access | Sequelize ORM used for the majority of CRUD queries | ⚠️ Partial | Raw string interpolation in routes/search.ts; Raw string interpolation in routes/login.ts | [F-009](#f-009) — SQL injection in product search<br/>[F-014](#f-014) — SQL injection in login |
| Request Access Logging | morgan middleware writes access log to stdout (and /support/logs/) | ⚠️ Partial | No structured security events; Logs exposed unauth at /support/logs | [F-032](#f-032) — Application logs served unauthenticated<br/>[F-048](#f-048) — Authentication events not logged |
| Multi-Factor Authentication | TOTP via otplib on standard login path | ⚠️ Partial | Not enforced on OAuth implicit-flow login; tmpToken issuance reuses the same hardcoded RSA key | [F-016](#f-016) — 2FA TOTP bypass |
| Container Hardening | Distroless base image reduces binaries but Dockerfile uses `FROM node:24` (floating tag) and `npm install --unsafe-perm` | ⚠️ Partial | FROM node:24 is not digest-pinned; npm install --unsafe-perm; No --ignore-scripts | [F-050](#f-050) — Supply-chain / container hygiene |
| Output Encoding | sanitize-html 1.4.2 applied to some stored user inputs; Angular template auto-escaping applied most places | 🔶 Weak | sanitize-html@1.4.2 — known bypasses; bypassSecurityTrustHtml used in search-result component and others | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()<br/>[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular |

_+2 additional controls — see [Section 7](#7-security-architecture) for the full catalog including ❌ Missing controls._

**Bottom line:** Security controls narrow specific attack surfaces but none eliminates a Critical finding on its own — all remaining Critical paths (SQL injection, hardcoded RSA key, JWT bypass, RCE via notevil) bypass the controls listed above.

---

## 1. System Overview

OWASP Juice Shop v19.2.1 is the world's most comprehensive intentionally vulnerable web application, maintained by OWASP volunteers as a security training and CTF platform. The application is a `Node.js`/Express monolith serving an Angular single-page application, backed by SQLite (via Sequelize) for structured data and MarsDB (an in-memory MongoDB-compatible store) for reviews and orders.

**Deployment context:** Docker container (`Node.js` 24, distroless base), single process, single host. No reverse proxy, no WAF, no API gateway in front of the Express server. Suitable for localhost or controlled lab environments — not production.

**Users:** Security professionals, developers, students, and CTF participants. The application intentionally exposes every OWASP Top 10 vulnerability and hundreds of additional security challenges.

**Compliance scope:** None (training app). The patterns mirror PCI-DSS and GDPR-relevant scenarios.

**Complexity tier:** Complex — 8 components analyzed, 47 threats identified across authentication, file handling, data persistence, frontend, and B2B processing layers.

**Context sources used:** `.threat-modeling-context.md` (Phase 1 cache hit), `.recon-summary.md` (Phase 2 full recon).

**Overall security assessment:** The application is intentionally broken across every security domain. The critical findings (hardcoded secrets, SQL injection, RCE) are real, confirmed, and exploitable. This document treats them as genuine threats because the patterns directly reflect vulnerabilities found in real production applications.

---

## 2. Architecture Diagrams

### 2.1 System Context

The context diagram shows who interacts with Juice Shop and which external services it depends on, grouped by trust zone.

```mermaid
graph TD
    subgraph INTERNET["Public Internet · untrusted"]
        ANON["Anonymous Visitor"]:::person
        CUST["Authenticated Customer"]:::person
        ATTACKER["Attacker"]:::person
    end

    subgraph DMZ["DMZ / Edge · no WAF or gateway"]
        JUICE["OWASP Juice Shop\nNode.js 24 / Express 4"]:::risk
    end

    subgraph INTERNAL["Internal / Localhost"]
        SQLITE["SQLite Database\n(Sequelize ORM)"]:::db
        MARSDB["MarsDB\n(In-Memory NoSQL)"]:::db
        FS["Local Filesystem\nftp/ uploads/ logs/"]:::system
    end

    subgraph EXTERNAL["External SaaS · untrusted"]
        GOOGLE["Google OAuth 2.0\n(implicit flow)"]:::external
    end

    ANON -->|"HTTP/S · public routes"| JUICE
    CUST -->|"HTTPS · authenticated routes"| JUICE
    ATTACKER -->|"HTTPS · all routes (no WAF)"| JUICE
    JUICE -->|"SQL · in-process"| SQLITE
    JUICE -->|"NoSQL · in-process"| MARSDB
    JUICE -->|"fs.write / serve-index"| FS
    JUICE -->|"OAuth redirect (implicit flow)"| GOOGLE

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Trust boundary enforcement summary:**

- **Internet → DMZ** — no enforcement: no WAF, no edge rate-limiting on most routes; unauthenticated management plane (`/ftp`, `/metrics`, `/support/logs`) co-located with the user API.
- **DMZ → Internal data** — in-process access: SQLite and MarsDB are embedded, not networked; authorization relies on ORM/collection-API-level checks, not a network boundary.
- **DMZ → External SaaS** — Google OAuth 2.0 implicit flow exposes the access token in the URL fragment; OAuth-linked account passwords are derived as `MD5(email)`, making them predictable to any email knower.

**Key takeaway:** All internet traffic reaches the Express monolith without any intermediate enforcement layer — no WAF, no API gateway, and no rate limiting at the edge for most routes.

### 2.2 Container Architecture

The container diagram shows the runtime architecture of the Express monolith and its internal service organization.

```mermaid
graph TD
    subgraph BROWSER["Browser · untrusted"]
        SPA["Angular SPA\n(TypeScript / Angular 20)"]:::risk
    end

    subgraph SERVER["Node.js Process · single container"]
        EXPRESS["Express 4 Server\nserver.ts"]:::risk
        AUTH["Auth Service\nlib/insecurity.ts"]:::risk
        ROUTES["Route Handlers\nroutes/ (50+ files)"]:::system
        FILE_HANDLER["File Upload Handler\nmulter, libxmljs2, unzipper, js-yaml"]:::risk
        B2B["B2B Order Processor\nnotevil + vm sandbox"]:::risk
        CHATBOT["Chatbot\njuicy-chat-bot"]:::system
        SOCKETIO["Socket.IO 3\n(WebSocket)"]:::system
    end

    subgraph DATA["Data Tier · restricted"]
        SQLITE["SQLite\n(Sequelize 6)"]:::db
        MARSDB["MarsDB\n(In-Memory)"]:::db
        FS["Filesystem\nuploads/ ftp/ logs/"]:::system
    end

    SPA -->|"HTTPS REST · Angular HttpClient"| EXPRESS
    SPA -->|"WSS · Socket.IO client"| SOCKETIO
    EXPRESS --> AUTH
    EXPRESS --> ROUTES
    EXPRESS --> FILE_HANDLER
    EXPRESS --> B2B
    EXPRESS --> CHATBOT
    ROUTES -->|"SQL · Sequelize ORM"| SQLITE
    ROUTES -->|"NoSQL · MarsDB API"| MARSDB
    FILE_HANDLER -->|"fs.write · uploads/"| FS
    EXPRESS -->|"serve-index · ftp/ logs/"| FS

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Trust boundary enforcement summary:**

- **Browser → Server** — HTTPS with no CSP and no HSTS; JWTs stored in browser `localStorage` are accessible to any same-origin XSS payload; `Socket.IO` WebSocket upgrade accepts any client without authentication.
- **Server → Data** — in-process database access; raw string interpolation in `routes/search.ts` and `routes/login.ts` defeats Sequelize's parameterization, creating SQL-injection vectors.
- **B2B → VM sandbox** (internal boundary, not a TB) — `notevil` + `vm.createContext()` evaluate user-supplied B2B expressions; prototype-pollution bypass of `notevil` enables server-side RCE in the `Node.js` host process.

**Key takeaway:** The Express monolith is a single process with no internal isolation — the B2B sandbox escape, file upload XXE, and SQL injection all share the same process boundary, so any exploit gives access to all other components.

### 2.3 Components

Eight security-relevant components were identified. Each has a stable anchor ID (`C-01` … `C-08`) used to cross-reference findings and mitigations throughout this document.

```mermaid
flowchart LR
    subgraph BROWSER["Browser · Untrusted"]
        C08["**C-08** Frontend SPA\nAngular 20"]:::risk
        C03["**C-03** Admin Panel\nclient-side route guard"]:::risk
    end

    subgraph SERVER["Node.js Process · Single Container"]
        C01["**C-01** REST API\nExpress routes/"]:::risk
        C02["**C-02** Auth Service\nlib/insecurity.ts"]:::risk
        C04["**C-04** B2B Orders\nnotevil + vm"]:::risk
        C05["**C-05** File Upload\nmulter + libxmljs2"]:::risk
        C06["**C-06** Chatbot\njuicy-chat-bot"]:::system
        C07["**C-07** Product Reviews\nMarsDB"]:::system
    end

    subgraph DATA["Data Tier"]
        SQLITE[("SQLite")]:::db
        MARSDB[("MarsDB")]:::db
        FS[/"Filesystem\nftp/ uploads/ logs/"/]:::risk
    end

    C08 -->|"HTTPS REST"| C01
    C03 -->|"HTTPS REST"| C01
    C01 --> C02
    C01 --> C04
    C01 --> C05
    C01 --> C06
    C01 --> C07
    C01 -->|"SQL · Sequelize + raw"| SQLITE
    C07 -->|"NoSQL · MarsDB API"| MARSDB
    C05 -->|"fs.write"| FS
    C01 -->|"serve-index · no auth"| FS

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

| ID | Component | Layer | Exposure | Key Implementation |
|----|-----------|-------|----------|--------------------|
| <a id="c-01"></a>[C-01](#c-01) | REST API | Server | Internet-facing — all HTTP routes | `routes/` (50+ handlers), Express 4 |
| <a id="c-02"></a>[C-02](#c-02) | Auth Service | Server | Internal — called by REST API | `lib/insecurity.ts`, jsonwebtoken 0.4.0, RSA key hardcoded |
| <a id="c-03"></a>[C-03](#c-03) | Admin Panel | Browser | Internet-facing — `/administration` | Angular route guard (client-side only, no server enforcement) |
| <a id="c-04"></a>[C-04](#c-04) | B2B Orders | Server | Internet-facing — `POST /b2b/v2/orders` | `notevil` + `vm.createContext()` expression evaluator |
| <a id="c-05"></a>[C-05](#c-05) | File Upload | Server | Internet-facing — `/file-upload`, `/rest/memories` | multer 1.4.5, libxmljs2 0.37, unzipper, js-yaml |
| <a id="c-06"></a>[C-06](#c-06) | Chatbot | Server | Internet-facing — `/rest/chatbot/*` | juicy-chat-bot, trainingData URL loaded from config |
| <a id="c-07"></a>[C-07](#c-07) | Product Reviews | Server | Internet-facing — `/rest/products/:id/reviews` | MarsDB (in-memory NoSQL), `$where` operator exposed |
| <a id="c-08"></a>[C-08](#c-08) | Frontend SPA | Browser | Internet-facing — all public routes | Angular 20, TypeScript, JWT stored in `localStorage` |

### 2.4 Technology Architecture

The technology stack from browser to data tier, showing protocols and deployment context.

```mermaid
graph TD
    subgraph BROWSER_TIER["Browser Tier"]
        NG["Angular 20 SPA\nTypeScript"]:::system
        LS["localStorage\n(JWT + PII)"]:::risk
    end

    subgraph APP_TIER["Application Tier — Node.js 24 Container"]
        EXP["Express 4.22\n(server.ts)"]:::risk
        HELM["Helmet 4.6\n(partial headers)"]:::system
        CORS_MW["cors()\n(wildcard)"]:::risk
        JWT_MW["express-jwt 0.1.3\njsonwebtoken 0.4.0"]:::risk
        MULTER["multer 1.4.5\n+ libxmljs2 0.37"]:::risk
        PUG["pug\n(userProfile SSTI)"]:::risk
        PROM["prom-client 14\n(/metrics unauthenticated)"]:::risk
    end

    subgraph DATA_TIER["Data Tier"]
        SQ["SQLite 3\n(Sequelize 6.37)"]:::db
        MD["MarsDB\n(in-memory NoSQL)"]:::db
        FTP["ftp/ directory\n(serve-index, public)"]:::risk
        LOGS["logs/ directory\n(serve-index, public)"]:::risk
        KEYS["encryptionkeys/\n(jwt.pub, premium.key, public)"]:::risk
    end

    NG -->|"HTTPS REST"| EXP
    NG -->|"WSS"| EXP
    LS -.->|"XSS-accessible"| NG
    EXP -->|"SQL · parameterized + raw"| SQ
    EXP -->|"NoSQL · in-process"| MD
    EXP -->|"HTTP · serve-index (no auth)"| FTP
    EXP -->|"HTTP · serve-index (no auth)"| LOGS
    EXP -->|"HTTP · serve-index (no auth)"| KEYS

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef db fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** Sensitive session material (JWT in localStorage) and critical infrastructure components (FTP directory, encryption keys) are all on the same tier with no network isolation, making lateral movement trivially easy after any initial compromise.

---

## 3. Attack Walkthroughs

This section shows step-by-step technical exploitation flows for the Critical findings. Each walkthrough uses two flows: the current vulnerable path (attack) and the post-mitigation path.

### 3.1 Attack Chain Overview

The diagram below shows how Critical findings combine into three attacker workflows — from unauthenticated internet access to full system compromise. The individual exploitation steps are detailed in the walkthroughs below.

```mermaid
graph TD
    ATTACKER["Internet Attacker\n(unauthenticated)"]:::person

    subgraph CHAIN1["Chain 1 — DB Compromise (no credentials)"]
        A1["GET /rest/products/search\n?q=UNION SELECT..."]:::risk
        A2["Full Users Table Dump\n(emails + MD5 hashes)"]:::risk
        A3["GPU MD5 Cracking\n(minutes)"]:::risk
    end

    subgraph CHAIN2["Chain 2 — Admin Takeover (repo access)"]
        B1["git clone\n(public repo)"]:::system
        B2["Extract RSA private key\nfrom lib/insecurity.ts:24"]:::risk
        B3["jwt.sign role:admin\n(offline)"]:::risk
        B4["POST /b2b/v2/orders\n{notevil payload}"]:::risk
        B5["RCE on Node.js\n(server process)"]:::risk
    end

    subgraph CHAIN3["Chain 3 — Mass Session Theft (XSS)"]
        C1["Store XSS payload\nvia product name"]:::risk
        C2["Victim browses\nproduct catalogue"]:::system
        C3["localStorage.getItem('token')\nexfiltrated"]:::risk
        C4["Account takeover\n(6h window)"]:::risk
    end

    ATTACKER -->|"F-009 SQLi"| A1
    A1 -->|"Users table"| A2
    A2 -->|"hashcat"| A3

    ATTACKER -->|"F-001 key exposed"| B1
    B1 --> B2
    B2 -->|"F-004 alg bypass"| B3
    B3 -->|"F-010 RCE"| B4
    B4 --> B5

    ATTACKER -->|"F-014 login bypass"| C1
    C1 -->|"F-024 XSS stored"| C2
    C2 -->|"F-008 localStorage"| C3
    C3 --> C4

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
```

**Key takeaway:** Chain 2 requires only a GitHub account and knowledge of JWT. The entire attack from key extraction to server-level code execution takes under 5 minutes with no network noise beyond the single B2B order POST.

<a id="wt-001"></a>

### 3.2 Offline JWT Forgery via Hardcoded RSA Key

This sequence shows how an attacker uses the publicly committed RSA private key to forge an admin JWT with no network interaction.

<!-- QA: sequence diagram alt branch should be labelled 'Current state — [T-001](#t-001)' per phase-group-architecture.md → "Phase 4: Attack Walkthroughs" fixed Section 8 semantics -->
```mermaid
sequenceDiagram
    participant ATTACKER as Attacker
    participant GITHUB as GitHub (public)
    participant JWT_LIB as jsonwebtoken (local)
    participant API as Juice Shop API

    alt Current state — T-001 (vulnerable flow)
        ATTACKER->>GITHUB: git clone https://github.com/juice-shop/juice-shop
        GITHUB-->>ATTACKER: Repository with lib/insecurity.ts:24 (RSA private key)
        ATTACKER->>JWT_LIB: jwt.sign(id=1 email=admin role=admin, privateKey, algorithm=RS256)
        JWT_LIB-->>ATTACKER: Valid RS256 signed JWT (role:admin)
        ATTACKER->>API: GET /api/Users Authorization:Bearer forged-admin-jwt
        API-->>ATTACKER: 200 OK — full user list with emails and password hashes
    else After M-001 — remove hardcoded key
        ATTACKER->>GITHUB: git clone (key removed)
        ATTACKER->>API: GET /api/Users Authorization:Bearer fabricated-jwt
        API-->>ATTACKER: 401 Unauthorized — server-side key loaded from env var, forgery fails
    end
```

<a id="wt-004"></a>

### 3.3 SQL Injection Login Bypass

This sequence shows SQL injection in the login endpoint allowing authentication without credentials.

<!-- QA: sequence diagram alt branch should be labelled 'Current state — [T-004](#t-004)' per phase-group-architecture.md → "Phase 4: Attack Walkthroughs" fixed Section 8 semantics -->
```mermaid
sequenceDiagram
    participant ATTACKER as Attacker
    participant LOGIN as POST /rest/user/login
    participant DB as SQLite Users Table

    alt Current state — T-004 (vulnerable flow)
        ATTACKER->>LOGIN: POST body: email=x OR 1=1 password=anything
        LOGIN->>DB: SELECT * FROM Users WHERE email=x OR 1=1 AND password=md5hash
        DB-->>LOGIN: Row 1 (admin@juice-sh.op, role:admin)
        LOGIN-->>ATTACKER: 200 OK with admin JWT — full application access
    else After M-004 — parameterized query
        ATTACKER->>LOGIN: POST body: email=SQLi-payload password=anything
        LOGIN->>DB: SELECT * FROM Users WHERE email=? AND password=? [bound params]
        DB-->>LOGIN: Empty result set (no matching user)
        LOGIN-->>ATTACKER: 401 Invalid email or password
    end
```

<a id="wt-010"></a>

### 3.4 RCE via notevil Sandbox Escape

This sequence shows how a B2B order with a crafted payload achieves remote code execution.

<!-- QA: sequence diagram alt branch should be labelled 'Current state — [T-010](#t-010)' per phase-group-architecture.md → "Phase 4: Attack Walkthroughs" fixed Section 8 semantics -->
```mermaid
sequenceDiagram
    participant ATTACKER as Attacker (any authenticated user)
    participant B2B as POST /b2b/v2/orders
    participant VM as vm.runInContext + notevil
    participant OS as Node.js process

    alt Current state — T-010 (vulnerable flow)
        ATTACKER->>B2B: POST orderLinesData containing prototype pollution payload
        B2B->>VM: vm.runInContext(safeEval orderLinesData, sandbox, timeout=2000)
        VM->>OS: Prototype pollution escapes sandbox
        OS-->>ATTACKER: Command output (id, /etc/passwd, env vars)
    else After M-008 — JSON schema validation
        ATTACKER->>B2B: POST orderLinesData containing prototype pollution payload
        B2B->>B2B: z.array(OrderLineSchema).parse(JSON.parse(orderLinesData))
        B2B-->>ATTACKER: 400 Bad Request — schema validation rejects non-conforming input
    end
```

<a id="wt-009"></a>

### 3.5 SQL Injection in Product Search

This sequence shows unauthenticated extraction of the Users table via the product search endpoint.

```mermaid
sequenceDiagram
    participant ATTACKER as Attacker (unauthenticated)
    participant SEARCH as GET /rest/products/search
    participant DB as SQLite Users Table

    alt Current state — T-009 (vulnerable flow)
        ATTACKER->>SEARCH: GET ?q=UNION SELECT id,email,password FROM Users
        SEARCH->>DB: SELECT * FROM Products WHERE name LIKE UNION SELECT id,email,password FROM Users
        DB-->>SEARCH: All rows from Users table (emails + MD5 hashes)
        SEARCH-->>ATTACKER: 200 OK — JSON array containing all user credentials
    else After M-004 — parameterized query
        ATTACKER->>SEARCH: GET ?q=UNION SELECT id,email,password FROM Users
        SEARCH->>DB: SELECT * FROM Products WHERE name LIKE ? [bound param]
        DB-->>SEARCH: Empty result (no products match the literal injection string)
        SEARCH-->>ATTACKER: 200 OK — empty product array, no user data
    end
```

---

## 4. Assets

Assets are classified by sensitivity and linked to the threats that put them at risk.

_Classification legend: **Restricted** — must be protected from all unauthorized access. **Confidential** — internal use only, regulated data. **Internal** — business-sensitive, not public. **Public** — intentionally public information._

| Asset | Classification | Description | Linked Threats |
|------- |---------------- |------------- |---------------- |
| User Credentials (email + password hash) | **Restricted** | All registered user emails and MD5-hashed passwords in SQLite Users table | [F-004](#f-004) — JWT alg:none bypass<br/>[F-009](#f-009) — SQL injection in product search<br/>[F-002](#f-002) — Password hashing uses MD5 without salt |
| JWT RSA Private Key | **Restricted** | Hardcoded in lib/insecurity.ts:24; used to sign all authentication tokens; publicly exposed on GitHub | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts<br/>[F-005](#f-005) — JWT signed with hardcoded key — admin impersonation<br/>[F-034](#f-034) — Prometheus /metrics unauthenticated |
| Application Configuration Secrets | **Restricted** | HMAC secret (lib/insecurity.ts:46), cookie secret ('kekse' server.ts), Google OAuth client ID | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts<br/>[F-023](#f-023) — Admin panel client-side guard only |
| Session Tokens (JWT in localStorage) | **Restricted** | RS256 JWTs stored in browser localStorage; carry user identity and role claims; extractable by XSS | [F-008](#f-008) — JWT stored in localStorage |
| Encryption Keys Directory | **Restricted** | jwt.pub and premium.key served via /encryptionkeys with directory listing and no authentication | [F-028](#f-028) — Unrestricted file type upload |
| Customer Orders and Payment Data | **Confidential** | Order history, wallet balances, payment card references in MarsDB and SQLite | [F-033](#f-033) — Hardcoded HMAC coupon key<br/>[F-021](#f-021) — OAuth implicit flow used in frontend |
| User PII (addresses, profile images) | **Confidential** | Postal addresses, uploaded profile images, memory captions associated with user accounts | [F-025](#f-025) — DOM XSS via innerHTML assignments in Angular<br/>[F-027](#f-027) — SSRF via profile image URL |
| Access Logs | **Internal** | HTTP access logs at logs/, browseable at /support/logs without authentication | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()<br/>[F-028](#f-028) — Unrestricted file type upload |
| FTP Directory Contents | **Internal** | Legacy files at /ftp including backups, coupon codes, database dumps; publicly accessible | [F-028](#f-028) — Unrestricted file type upload |
| Prometheus Metrics | **Internal** | Application telemetry at /metrics — request rates, challenge solve rates, heap statistics | [F-042](#f-042) — User data leakage via username injection |
| Product Catalog and Reviews | **Public** | Product names, descriptions, user-authored reviews in SQLite and MarsDB | [F-020](#f-020) — Mass update IDOR in reviews<br/>[F-022](#f-022) — OAuth predictable password derived as MD5(email) |

## 5. Attack Surface

The attack surface is split by authentication requirement. Unauthenticated entry points are the highest-risk targets as they are reachable by any internet-connected attacker without credentials.

### 5.1 Unauthenticated Entry Points (12)

These endpoints accept requests without a valid session token.

| # | Entry Point | Protocol | Method | Notes | Linked Threats |
|--- |------------- |---------- |-------- |------- |---------------- |
| E-01 | `/rest/user/login` | HTTPS | POST | No rate limiting, SQL injectable | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts<br/>[F-004](#f-004) — JWT alg:none bypass |
| E-02 | `/rest/user/reset-password` | HTTPS | POST | Predictable security questions | [F-015](#f-015) — Password reset via guessable security answers |
| E-03 | `/rest/products/search` | HTTPS | GET | SQL injectable `q` parameter | [F-009](#f-009) — SQL injection in product search |
| E-04 | `/api/Users` (registration) | HTTPS | POST | Mass assignment, no rate limiting | [F-011](#f-011) — Mass assignment in user registration |
| E-05 | `/rest/user/whoami` | HTTPS | GET | No auth required, leaks user info | [F-034](#f-034) — Prometheus /metrics unauthenticated |
| E-06 | `/file-upload` | HTTPS | POST | XXE, ZIP traversal, YAML bomb | [F-006](#f-006) — XXE via libxml2 with noent:true<br/>[F-007](#f-007) — ZIP Slip path traversal in routes/fileUpload.ts<br/>[F-028](#f-028) — Unrestricted file type upload |
| E-07 | `/profile/image/url` | HTTPS | POST | SSRF via URL fetch | [F-029](#f-029) — CPU exhaustion DoS via complex expression |
| E-08 | `/metrics` | HTTP | GET | Prometheus metrics, no auth | [F-034](#f-034) — Prometheus /metrics unauthenticated |
| E-09 | `/ftp/` | HTTP | GET | Directory listing, sensitive files | [F-012](#f-012) — Unauthenticated /ftp directory listing |
| E-10 | `/redirect` | HTTPS | GET | Open redirect via `to` param | [F-037](#f-037) — Open redirect via to parameter |
| E-11 | OAuth `/authorize` callback | HTTPS | GET | Implicit flow, predictable password | [F-021](#f-021) — OAuth implicit flow used in frontend<br/>[F-022](#f-022) — OAuth predictable password derived as MD5(email) |
| E-12 | `/socket.io` WebSocket | WSS | CONNECT | Unauthenticated WebSocket upgrade | [F-040](#f-040) — Sensitive data in localStorage |

### 5.2 Authenticated Entry Points (5)

These endpoints require a valid JWT but are accessible to any registered user (not admin-only).

| # | Entry Point | Protocol | Method | Auth Level | Notes | Linked Threats |
|--- |------------- |---------- |-------- |------------ |------- |---------------- |
| E-13 | `/api/BasketItems` | HTTPS | GET/POST/PUT | Any JWT | IDOR — no ownership check | [F-018](#f-018) — IDOR on basket and order endpoints |
| E-14 | `/api/Users` | HTTPS | GET | Any JWT | Returns full user list including hashed passwords | [F-013](#f-013) — Full user list accessible to any authenticated user |
| E-15 | `/rest/products/:id/reviews` | HTTPS | GET/PUT | Any JWT | NoSQL injection, mass update IDOR | [F-019](#f-019) — NoSQL injection via $where in reviews<br/>[F-020](#f-020) — Mass update IDOR in reviews |
| E-16 | `/api/Orders` | HTTPS | GET | Any JWT | IDOR — returns other users' orders | [F-018](#f-018) — IDOR on basket and order endpoints |
| E-17 | `/rest/chatbot/respond` | HTTPS | POST | Any JWT | Admin functions without role check | [F-030](#f-030) — Chatbot admin functions without role check |

---

## 7. Security Architecture

This chapter consolidates the **architectural narrative** (patterns, per-domain assessment, cross-cutting topics) with the **canonical control catalog** (39 controls). Each domain contains both the architectural reasoning and the controls that implement — or fail to implement — it.

**Reading guide**
- [§7.1 Overview](#71-overview) — architecture patterns, overall rating
- [§7.2 Key Architectural Risks](#72-key-architectural-risks) — cross-cutting root defects (→ [§8.D Architectural Findings](#8d-architectural-findings))
- [§7.3](#73-identity--access-management)..[§7.12](#712-dependency--supply-chain) — Per-domain narrative + controls
- [§7.13 Secret Management](#713-secret-management) — cross-cutting
- [§7.14 Defense-in-Depth Assessment](#714-defense-in-depth-assessment) — cross-cutting

**Catalog totals:** ✅ 1 Adequate · ⚠️ 8 Partial · 🔶 8 Weak · ❌ 22 Missing · 39 controls tracked.

**Gap summary:** The three most impactful control gaps are **Content Security Policy** ([§7.7 SC-21](#77-frontend-security)), **Security Event Logging** ([§7.10 SC-28](#710-audit--logging)) and **Web Application Firewall** ([§7.11 SC-34](#711-infrastructure--network-segmentation)) — each would mitigate 3+ Critical/High findings. The Management Summary's **Operational Strengths** view is an automatic filter over this catalog: rows with `effectiveness ∈ {Adequate, Partial, Weak}` and `show_in_strengths_by_default: true`.

**Effectiveness legend:** ✅ Adequate · ⚠️ Partial · 🔶 Weak · ❌ Missing

---

### 7.1 Overview

#### Architecture Patterns

Eight core security patterns assessed against the current implementation. Each row links to the domain section(s) that track the corresponding controls.

| Pattern | Status | Assessment | See also |
|--------- |-------- |------------ |---------- |
| API Gateway / WAF | ❌ Absent | No gateway, no WAF, no reverse proxy in front of Express. All traffic hits the application directly — including management endpoints (`/metrics`, `/ftp`, `/encryptionkeys`). | [§7.11](#711-infrastructure--network-segmentation) SC-34, SC-35 |
| Defense-in-depth | ❌ Absent | A single bypass (SQLi or `alg:none`) grants full application access. No compensating controls at any layer. | [§7.14](#714-defense-in-depth-assessment) |
| Separation of concerns | ⚠️ Partial | Auth logic centralized in `lib/insecurity.ts` but contains hardcoded secrets; route handlers access models directly with no service layer. | [§7.3](#73-identity--access-management), [§7.13](#713-secret-management) |
| Least privilege | ❌ Absent | Application process has full filesystem write access; DB queries run with no row-level permissions; admin role is self-assignable. | [§7.4](#74-authorization) |
| Secrets management | ❌ Absent | All cryptographic secrets (RSA key, HMAC, cookie secret) hardcoded in public source. | [§7.13](#713-secret-management) SC-04 |
| Network segmentation | ❌ Absent | Single flat network, no DMZ; management endpoints on the same listener as the user API. | [§7.11](#711-infrastructure--network-segmentation) SC-35 |
| Secure defaults | ❌ Absent | CORS wildcard, no CSP, development mode active, no rate limiting on login, no input validation on critical endpoints. | [§7.7](#77-frontend-security), [§7.5](#75-input-validation--output-encoding) |
| BFF / Proxy pattern | ❌ Absent | OAuth Implicit Flow exposes access tokens to the browser; no server-side token exchange. | [§7.3](#73-identity--access-management) SC-05 |

**Assessment:** Eight of eight core patterns are absent or only partially implemented.

#### Overall Architecture Security Rating

🔴 **Critical gaps** — The architecture has no effective security boundary at any layer. The combination of publicly exposed cryptographic secrets, raw SQL string interpolation, eval-equivalent code execution, and JWT persistence in `localStorage` creates an attack surface where an unauthenticated internet attacker can achieve server-level code execution in a single request sequence. This is intentional for a training platform but maps precisely to classes of defects found in real production applications — every finding in this report has a real-world parallel.

---

### 7.2 Key Architectural Risks

Cross-cutting architectural defects that drive **~40% of all findings**. Each row anchors in [§8.D Architectural Findings](#8d-architectural-findings).

| Risk | Structural Defect | Why this matters | Linked |
|------ |------------------- |------------------ |-------- |
| 🔴 | **Monolith with no separation** — authentication, business logic, file handling, and code execution all share one `Node.js` process | A single RCE or privilege escalation in any component gives unrestricted access to all others and their data | [F-010](#f-010) — RCE via notevil sandbox escape[F-037](#f-037) — Open redirect via to parameter[AF-001](#af-001) |
| 🔴 | **All secrets in source code** — private key, HMAC secret, cookie secret checked into a public repository | The threat model cannot be fixed through runtime configuration alone; secrets must be treated as permanently compromised and rotated | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts[F-023](#f-023) — Admin panel client-side guard only[AF-002](#af-002) |
| 🔴 | **Unsafe code execution pattern** — user-supplied strings passed through an eval-equivalent (`notevil` + `vm`) | No input sanitization scheme can make `eval()` of untrusted input safe; the architectural choice is the root defect | [F-010](#f-010) — RCE via notevil sandbox escape[F-030](#f-030) — Chatbot admin functions without role check[AF-003](#af-003) |
| 🟠 | **Unauthenticated management plane** — `/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics` all accessible without auth | An attacker gains a complete operational picture of the server before attempting any exploit | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()[F-028](#f-028) — Unrestricted file type upload[F-042](#f-042) — User data leakage via username injection[AF-005](#af-005) |
| 🟠 | **Browser-resident session material** — JWT stored in `localStorage` accessible to any same-origin JavaScript | XSS impact amplified from UI defacement to full account takeover at scale | [F-008](#f-008) — JWT stored in localStorage[F-045](#f-045) — OAuth implicit flow token in URL fragment[AF-006](#af-006) |

---

### 7.3 Identity & Access Management

#### Authentication landscape

The application exposes four authentication flows and one unauthenticated service-plane path. All credential-bearing flows converge on a single shared JWT trust anchor (`express-jwt 0.1.3`). Each flow is documented in its own subsection below.

| Flow | Entry-Point | Status | Detail |
|------|-------------|--------|--------|
| Password Login | `/rest/user/login` | 🔴 Broken | [§ 7.3.1](#flow-password) |
| 2FA / TOTP | `/rest/2fa/verify` | 🔶 Weak | [§ 7.3.2](#flow-2fa) |
| Password Reset | `/rest/user/reset-password` | 🔶 Weak | [§ 7.3.3](#flow-reset) |
| Google OAuth 2.0 | `/rest/user/login/google` | 🔶 Weak | [§ 7.3.4](#flow-oauth) |
| `Socket.IO` WebSocket | `/socket.io` | ❌ Missing | [§ 7.3.5](#flow-websocket) |

---

<a id="flow-password"></a>
##### 7.3.1 Password Login

The primary authentication path. The user submits email and password; the server queries SQLite for a matching record and, on success, issues a signed JWT. Two critical defects undermine the entire flow independently: the SQL query is built via raw string interpolation (SQL injection), and passwords are stored as unsalted MD5 hashes (trivially crackable offline). The JWT is signed with an RSA key that is committed to the public repository.

```mermaid
sequenceDiagram
    participant B as Browser
    participant L as Login endpoint
    participant DB as SQLite
    participant MW as JWT middleware
    participant R as Route handler

    B->>L: POST /rest/user/login (email + password)
    Note right of L: [F-014] Raw SQL string interpolation
    L->>DB: SELECT * FROM Users WHERE email=... AND password=md5(...)
    DB-->>L: user row (or injected result set)
    Note right of L: [F-002] Password stored as unsalted MD5

    L-->>B: JWT (RS256, hardcoded key)
    Note right of B: [F-001] Signing key is committed to public repo
    Note right of B: [F-008] JWT written to localStorage

    B->>MW: GET /api/... Authorization Bearer token
    Note right of MW: [F-004] alg:none accepted — no algorithm whitelist
    Note right of MW: [F-035] No jti claim — no server-side revocation
    MW-->>R: req.user from JWT claims
```

| Severity | Finding |
|----------|---------|
| 🔴 Critical | [F-014](#f-014) — SQL injection in login |
| 🔴 Critical | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts |
| 🔴 Critical | [F-004](#f-004) — JWT alg:none bypass |
| 🔴 Critical | [F-008](#f-008) — JWT stored in localStorage |
| 🔴 Critical | [F-002](#f-002) — Password hashing uses MD5 without salt |
| 🟠 High | [F-035](#f-035) — Auth token revocation absent |
| 🟠 High | [F-036](#f-036) — No rate limiting on auth endpoints |
| 🟠 High | [F-038](#f-038) — No account lockout on failed logins |

---

<a id="flow-2fa"></a>
##### 7.3.2 Two-Factor Authentication (TOTP)

After a successful password login, users with 2FA enabled receive a short-lived `tmpToken` and must submit a TOTP code to exchange it for a full JWT. The `tmpToken` is signed with the same hardcoded RSA key used for all other tokens — meaning an attacker who has cloned the repository can forge a valid `tmpToken` and bypass the second factor entirely. Additionally, the OAuth login path skips 2FA verification altogether.

```mermaid
sequenceDiagram
    participant B as Browser
    participant L as Login endpoint
    participant T as 2FA endpoint
    participant MW as JWT middleware
    participant R as Route handler

    B->>L: POST /rest/user/login (credentials — 2FA enabled)
    L-->>B: 200 tmpToken (RS256, same hardcoded key)
    Note right of L: [F-016] tmpToken uses the same compromised signing key

    B->>T: POST /rest/2fa/verify (tmpToken + TOTP code)
    Note right of T: OAuth login path skips this step entirely
    T-->>B: full JWT (RS256, hardcoded key)

    B->>MW: GET /api/... Authorization Bearer token
    Note right of MW: [F-004] alg:none accepted
    MW-->>R: req.user from JWT claims
```

| Severity | Finding |
|----------|---------|
| 🟠 High | [F-016](#f-016) — 2FA TOTP bypass |
| 🔴 Critical | [F-004](#f-004) — JWT alg:none bypass |

---

<a id="flow-reset"></a>
##### 7.3.3 Password Reset

Users who forget their password answer a security question they chose at registration. A correct answer allows setting a new password without any email verification or rate limiting. Security questions are inherently weak credentials — answers are often guessable, publicly available (social media), or reusable across sites.

```mermaid
sequenceDiagram
    participant B as Browser
    participant R as Reset endpoint
    participant DB as SQLite

    B->>R: GET /rest/user/security-question?email=...
    R-->>B: security question text

    B->>R: POST /rest/user/reset-password (email + answer + newPassword)
    Note right of R: [F-015] Answer to a free-text question is the only credential
    Note right of R: No email OTP, no rate limiting on answer attempts
    R->>DB: UPDATE Users SET password=md5(newPassword) WHERE email=...
    Note right of R: [F-002] New password stored as unsalted MD5
    DB-->>R: ok
    R-->>B: 200 Password changed
```

| Severity | Finding |
|----------|---------|
| 🟠 High | [F-015](#f-015) — Password reset via guessable security answers |
| 🔴 Critical | [F-002](#f-002) — Password hashing uses MD5 without salt |
| 🟠 High | [F-036](#f-036) — No rate limiting on auth endpoints |

---

<a id="flow-oauth"></a>
##### 7.3.4 Google OAuth 2.0

Optional federated login via Google. The application uses the deprecated OAuth 2.0 Implicit Flow: the access token is returned in the URL fragment, exposing it to browser history and referrer headers. On the server side, every OAuth-linked account is assigned a local password of `MD5(email)` — predictable by anyone who knows the user's email address, rendering the OAuth credential irrelevant for account takeover.

```mermaid
sequenceDiagram
    participant B as Browser
    participant G as Google OAuth 2.0
    participant CB as Callback endpoint
    participant DB as SQLite
    participant MW as JWT middleware
    participant R as Route handler

    B->>G: Redirect — Implicit Flow (response_type=token, no PKCE, no state)
    Note right of G: [F-021] Implicit Flow is deprecated per RFC 8252
    G-->>B: Redirect to /rest/user/login/google#access_token=...
    Note right of B: [F-045] Token in URL fragment — exposed to history and referrer

    B->>CB: POST access_token (extracted from fragment by frontend)
    CB->>G: Validate access token
    G-->>CB: user email

    CB->>DB: Find or create user by email
    Note right of CB: [F-022] Account password set to MD5(email)
    DB-->>CB: user row

    CB-->>B: JWT (RS256, same hardcoded key)
    Note right of B: [F-001] Signing key is committed to public repo
    Note right of B: [F-008] JWT written to localStorage

    B->>MW: GET /api/... Authorization Bearer token
    Note right of MW: [F-004] alg:none accepted
    Note right of MW: [F-035] No revocation list
    MW-->>R: req.user from JWT claims
```

| Severity | Finding |
|----------|---------|
| 🟠 High | [F-021](#f-021) — OAuth implicit flow used in frontend |
| 🟠 High | [F-022](#f-022) — OAuth predictable password derived as MD5(email) |
| 🟠 High | [F-045](#f-045) — OAuth implicit flow token in URL fragment |
| 🔴 Critical | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts |
| 🔴 Critical | [F-004](#f-004) — JWT alg:none bypass |
| 🔴 Critical | [F-008](#f-008) — JWT stored in localStorage |

---

<a id="flow-websocket"></a>
##### 7.3.5 `Socket.IO` WebSocket

The `Socket.IO` server runs on the same host and port as the REST API but applies no authentication middleware to the WebSocket upgrade. Any client — authenticated or not — can connect and emit challenge-verification events. This path completely bypasses all token-based controls established by the flows above.

```mermaid
sequenceDiagram
    participant B as Browser
    participant IO as Socket.IO server
    participant CH as Challenge handler

    B->>IO: GET /socket.io (WebSocket upgrade)
    Note right of IO: [F-049] No io.use() middleware — upgrade accepted unconditionally
    IO-->>B: 101 Switching Protocols

    B->>IO: emit verifyLocalXssChallenge (attacker payload)
    Note right of IO: No origin validation, no rate limiting
    IO->>CH: process event with client-supplied data
    CH-->>B: challenge result
```

| Severity | Finding |
|----------|---------|
| 🔴 Critical | [F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade |

---

**Cross-flow structural defects:**
- Shared trust anchor (RSA key) is public — **all credential-bearing flows are simultaneously compromised** by cloning the repository.
- `express-jwt 0.1.3` is 8+ major versions behind; `algorithms:[…]` not enforced — `alg:none` accepted on all flows.
- No `jti`-based revocation; logout is purely client-side — a stolen token remains valid until expiry.

**Target architecture:**
- Upgrade `express-jwt` to ≥9.x with `algorithms:['RS256']` enforced; load private key from environment variable with startup assertion.
- Migrate OAuth to **Authorization Code + PKCE** with server-side token exchange (retire Implicit Flow).
- Move JWT from `localStorage` to `HttpOnly; Secure; SameSite=Lax` cookie — see [F-008](#f-008) — JWT stored in localStorage and [§7.6](#76-data-protection--session-management).
- Introduce `jti` + Redis-backed revocation list; issue 2FA `tmpToken` with a short-lived, independently keyed secret.
- Apply JWT-verify middleware via `io.use()` on the `Socket.IO` listener.
- Replace security-question reset with email OTP ([M-011](#m-011) — Replace security questions with email OTP).

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-03"></a>SC-03 | Password Hashing | `crypto.createHash('md5')` raw hash with no salt<br/>_[lib/insecurity.ts:10-14](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)_ | ❌ Missing | expected: [F-002](#f-002) — Password hashing uses MD5 without salt[F-022](#f-022) — OAuth predictable password derived as MD5(email) | ➚ [CWE-916](https://cwe.mitre.org/data/definitions/916.html), ➚ [CWE-327](https://cwe.mitre.org/data/definitions/327.html), ASVS V2.4, NIST IA-5 |
| <a id="sc-04"></a>SC-04 | Secret Management | Secrets embedded in source (RSA private key, HMAC key, OAuth client secret, cookie secret)<br/>_[lib/insecurity.ts:21-46](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)_ | ❌ Missing | expected: [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts[F-033](#f-033) — Hardcoded HMAC coupon key | ➚ [CWE-321](https://cwe.mitre.org/data/definitions/321.html), ➚ [CWE-798](https://cwe.mitre.org/data/definitions/798.html), ASVS V6.4, NIST SC-12 · _see [§7.13](#713-secret-management)_ |
| <a id="sc-01"></a>SC-01 | JWT Signature Verification | `express-jwt` middleware + `jws.verify()` with public key<br/>_[lib/insecurity.ts:20-45](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)_ | 🔶 Weak | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts[F-004](#f-004) — JWT alg:none bypass[F-005](#f-005) — JWT signed with hardcoded key — admin impersonation | ➚ [CWE-347](https://cwe.mitre.org/data/definitions/347.html), ➚ [CWE-290](https://cwe.mitre.org/data/definitions/290.html), ASVS V3.5, NIST IA-5 |
| <a id="sc-05"></a>SC-05 | Federated Identity / OAuth | Google OAuth 2.0 Implicit Flow with token delivered in URL fragment; OAuth-linked password derived as MD5(email)<br/>_[lib/insecurity.ts:60-80](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)_ | 🔶 Weak | [F-021](#f-021) — OAuth implicit flow used in frontend[F-022](#f-022) — OAuth predictable password derived as MD5(email)[F-045](#f-045) — OAuth implicit flow token in URL fragment | ➚ [CWE-287](https://cwe.mitre.org/data/definitions/287.html), ➚ [CWE-522](https://cwe.mitre.org/data/definitions/522.html), ASVS V2.1 |
| <a id="sc-31"></a>SC-31 | Authentication Rate Limiting | `express-rate-limit` on `/rest/user/reset-password` and `/rest/user/2fa-verify`<br/>_[server.ts:70-90](vscode://file/home/mrohr/juice-shop/server.ts)_ | 🔶 Weak | [F-036](#f-036) — No rate limiting on auth endpoints[F-038](#f-038) — No account lockout on failed logins | ➚ [CWE-307](https://cwe.mitre.org/data/definitions/307.html), ASVS V2.2 |
| <a id="sc-02"></a>SC-02 | Multi-Factor Authentication | TOTP via `otplib` on standard login path<br/>_[routes/2fa.ts:1-89](vscode://file/home/mrohr/juice-shop/routes/2fa.ts)_ | ⚠️ Partial | [F-016](#f-016) — 2FA TOTP bypass | ➚ [CWE-287](https://cwe.mitre.org/data/definitions/287.html), ➚ [CWE-308](https://cwe.mitre.org/data/definitions/308.html), ASVS V2.1, NIST IA-2 |

_Domain summary: ✅ 0 · ⚠️ 1 · 🔶 3 · ❌ 2 (6 controls total)._

---

### 7.4 Authorization

**Current state:** Role claims are pulled from the JWT payload. Helpers `isAccounting()` / `isDeluxe()` / `isAdmin()` live in `lib/insecurity.ts`. The admin panel is enforced **only** client-side in Angular; no server-side RBAC on `/api/Users`.

**Structural defects:**
- No centralized Policy Decision Point — role is a plain JWT claim, self-attestable via mass-assignment ([F-011](#f-011) — Mass assignment in user registration
- Admin role enforced inconsistently — several routes check `isAuthorized()` but do not verify the role value.
- Object-level authorization (IDOR) absent on basket, order, and review endpoints.
- `denyAll()` middleware exists on challenge routes but doesn't protect the admin panel.

**Target architecture:** Add `ensureRole('admin')` middleware on every privileged route. Implement ownership checks (`basket.userId === jwt.sub`) on per-object endpoints. Deny unknown roles at the framework level.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-08"></a>SC-08 | Object-Level Authorization | None — routes use `:id` parameter without ownership check | ❌ Missing | expected: [F-018](#f-018) — IDOR on basket and order endpoints[F-020](#f-020) — Mass update IDOR in reviews | ➚ [CWE-639](https://cwe.mitre.org/data/definitions/639.html), ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html), ASVS V4.2 |
| <a id="sc-07"></a>SC-07 | Role-Based Access Control | `isAccounting()` / `isDeluxe()` / `isAdmin()` role checks on a subset of routes<br/>_[lib/insecurity.ts:120-160](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)_ | ⚠️ Partial | [F-010](#f-010) — RCE via notevil sandbox escape[F-013](#f-013) — Full user list accessible to any authenticated user[F-023](#f-023) — Admin panel client-side guard only[F-030](#f-030) — Chatbot admin functions without role check[F-046](#f-046) — Admin user deletion without safeguards | ➚ [CWE-285](https://cwe.mitre.org/data/definitions/285.html), ➚ [CWE-862](https://cwe.mitre.org/data/definitions/862.html), ASVS V4.1, NIST AC-3 |
| <a id="sc-09"></a>SC-09 | Explicit Deny Baseline | `denyAll()` middleware applied to challenge-related routes<br/>_[lib/insecurity.ts:200-220](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)_ | ⚠️ Partial | [F-013](#f-013) — Full user list accessible to any authenticated user[F-023](#f-023) — Admin panel client-side guard only[F-030](#f-030) — Chatbot admin functions without role check | ➚ [CWE-862](https://cwe.mitre.org/data/definitions/862.html), ASVS V4.1 |

_Domain summary: ✅ 0 · ⚠️ 2 · 🔶 0 · ❌ 1 (3 controls total)._

---

### 7.5 Input Validation & Output Encoding

**Current state:** There is no centralized input validator. Individual routes use:
- `sanitize-html 1.4.2` (8-year-old version with known bypasses) on some stored inputs.
- `sanitize-filename` on upload filenames.
- Angular's built-in sanitizer for most templates — but **explicitly bypassed** via `DomSanitizer.bypassSecurityTrustHtml()` in the search-result component.
- Raw SQL string interpolation in two routes (login, product search).
- NoSQL `$where` receives unsanitized input in reviews.
- `libxmljs2` configured with `noent:true` (XXE-enabled).
- `notevil` + `vm` executes user input in a bypassable sandbox.

**Structural defects:** Five distinct injection classes reachable from HTTP input — SQLi, NoSQLi, XXE, XSS (via bypass), RCE (via notevil). No schema validator (zod/ajv/joi) on any untrusted route body.

**Target architecture:** Introduce `zod` schemas at each route entry. Parameterize every database query. Remove eval-equivalent patterns — see [§7.2 Risk #3](#72-key-architectural-risks). Upgrade `sanitize-html`; remove the `DomSanitizer` bypass.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-11"></a>SC-11 | Input Schema Validation | No centralized schema validator (zod/ajv/joi) on untrusted route bodies | ❌ Missing | expected: [F-011](#f-011) — Mass assignment in user registration[F-010](#f-010) — RCE via notevil sandbox escape | ➚ [CWE-20](https://cwe.mitre.org/data/definitions/20.html), ➚ [CWE-915](https://cwe.mitre.org/data/definitions/915.html), ASVS V5.1 |
| <a id="sc-14"></a>SC-14 | Sandbox Isolation | `notevil` library + `vm.createContext()` used to evaluate B2B order expressions<br/>_[routes/b2bOrder.ts:30-55](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts)_ | ❌ Missing | expected: [F-010](#f-010) — RCE via notevil sandbox escape[F-029](#f-029) — CPU exhaustion DoS via complex expression | ➚ [CWE-94](https://cwe.mitre.org/data/definitions/94.html), ➚ [CWE-502](https://cwe.mitre.org/data/definitions/502.html), ASVS V5.5 |
| <a id="sc-13"></a>SC-13 | Mass-Assignment Prevention | None — `req.body` passed directly to `User.create()` | ❌ Missing | expected: [F-011](#f-011) — Mass assignment in user registration | ➚ [CWE-915](https://cwe.mitre.org/data/definitions/915.html), ASVS V5.1 |
| <a id="sc-12"></a>SC-12 | Output Encoding (frontend) | `sanitize-html 1.4.2` applied to some stored user inputs; Angular template auto-escape applied most places | 🔶 Weak | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular | ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ASVS V5.2 |
| <a id="sc-10"></a>SC-10 | Parameterized Database Access | Sequelize ORM used for the majority of CRUD queries | ⚠️ Partial | [F-009](#f-009) — SQL injection in product search[F-014](#f-014) — SQL injection in login | ➚ [CWE-89](https://cwe.mitre.org/data/definitions/89.html), ➚ [CWE-943](https://cwe.mitre.org/data/definitions/943.html), ASVS V5.3 |
| <a id="sc-15"></a>SC-15 | Upload Filename Encoding | `sanitize-filename` on file upload names<br/>_[routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts)_ | ✅ Adequate | — | ➚ [CWE-22](https://cwe.mitre.org/data/definitions/22.html), ASVS V12.3 |

_Domain summary: ✅ 1 · ⚠️ 1 · 🔶 1 · ❌ 3 (6 controls total)._

---

### 7.6 Data Protection & Session Management

**Current state:**
- **Data at rest:** SQLite file (no DB-level encryption); MarsDB in-memory for reviews.
- **Data in transit:** TLS terminated at a reverse proxy — the application itself does not enforce TLS or HSTS.
- **Session representation:** stateless JWT; no server-side session store.
- **Client storage:** JWT and PII in `localStorage`, readable by any same-origin JavaScript.
- **Session revocation:** none — stateless JWTs have no blocklist; logout only clears `localStorage` while the server still honours any copied token until expiry.

**Structural defects:** A single process holds all decrypted data. Browser-resident JWT combined with XSS ([F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular[§7.2 Risk #1](#72-key-architectural-risks)) and data-holding components.

**Target architecture:** Move JWT into `HttpOnly; Secure; SameSite=Lax` cookie; maintain a `jti`-keyed revocation blocklist (Redis) with explicit logout endpoint. Encrypt PII at rest (`pgcrypto` / KMS). Enforce TLS in-app via HSTS. Consider a separate worker process for file handling and code evaluation so that an RCE in one does not reach the other's data.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-19"></a>SC-19 | Client-Side Storage Safety | JWT + user PII stored in `localStorage`; no HttpOnly cookies | ❌ Missing | expected: [F-008](#f-008) — JWT stored in localStorage[F-040](#f-040) — Sensitive data in localStorage | ➚ [CWE-922](https://cwe.mitre.org/data/definitions/922.html), ASVS V3.4 |
| <a id="sc-17"></a>SC-17 | TLS Certificate Management | None — no certificate pinning, rotation, or mTLS | ❌ Missing | — | ASVS V9.1 |
| <a id="sc-18"></a>SC-18 | Data at Rest Encryption | No DB-level encryption; SQLite file on disk, MarsDB in-memory | ❌ Missing | — | ➚ [CWE-311](https://cwe.mitre.org/data/definitions/311.html), ASVS V6.2 |
| <a id="sc-06"></a>SC-06 | Session Token Revocation | None — stateless JWTs with no blocklist | ❌ Missing | expected: [F-035](#f-035) — Auth token revocation absent | ➚ [CWE-613](https://cwe.mitre.org/data/definitions/613.html), ASVS V3.3, NIST AC-12 |
| <a id="sc-16"></a>SC-16 | Transport Layer Security | App does not enforce TLS itself — relies on reverse proxy / load balancer | ⚠️ Partial | [F-017](#f-017) — CSRF on password change | ➚ [CWE-319](https://cwe.mitre.org/data/definitions/319.html), ASVS V9.1, NIST SC-8 |

_Domain summary: ✅ 0 · ⚠️ 1 · 🔶 0 · ❌ 4 (5 controls total)._

---

### 7.7 Frontend Security

**Current state:** The Angular SPA uses template auto-escape for most bindings, but bypasses the sanitizer in the search-result component and writes via `innerHTML` in several places. No Content-Security-Policy is set; CORS is wildcard (`*`) with credentials enabled; no CSRF tokens; no `SameSite` attribute on cookies. Helmet is wired in but only provides `X-Content-Type-Options` and `X-Frame-Options`. Open-redirect guard uses a weak substring prefix check.

**Structural defects:** Three distinct vectors reach the user's DOM with attacker input — `DomSanitizer` bypass, `innerHTML` writes, and open-redirect chaining. Combined with the browser-resident JWT ([§7.6](#76-data-protection--session-management)), any successful XSS is a full session-takeover.

**Target architecture:** Apply a report-only CSP first, then enforce with `script-src 'self'`. Restrict CORS to the SPA origin, disable wildcard. Add CSRF tokens on state-changing routes. Remove `DomSanitizer.bypassSecurityTrustHtml()`; audit all `innerHTML` writes.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-21"></a>SC-21 | Content Security Policy | No `Content-Security-Policy` header set | ❌ Missing | expected: [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular[F-039](#f-039) — Missing Content Security Policy | ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html), ASVS V14.4 |
| <a id="sc-22"></a>SC-22 | CORS Policy | `app.use(cors())` — wildcard `Access-Control-Allow-Origin`<br/>_[server.ts:180-184](vscode://file/home/mrohr/juice-shop/server.ts)_ | ❌ Missing | expected: [F-031](#f-031) — CORS wildcard Access-Control-Allow-Origin: * | ➚ [CWE-942](https://cwe.mitre.org/data/definitions/942.html), ASVS V14.5 |
| <a id="sc-23"></a>SC-23 | CSRF Protection | No CSRF token middleware; no `SameSite` cookie flag | ❌ Missing | expected: [F-017](#f-017) — CSRF on password change | ➚ [CWE-352](https://cwe.mitre.org/data/definitions/352.html), ASVS V4.2 |
| <a id="sc-24"></a>SC-24 | Open Redirect Prevention | Weak substring prefix check on `/redirect` `to` parameter<br/>_[routes/redirect.ts:10-25](vscode://file/home/mrohr/juice-shop/routes/redirect.ts)_ | 🔶 Weak | [F-037](#f-037) — Open redirect via to parameter | ➚ [CWE-601](https://cwe.mitre.org/data/definitions/601.html), ASVS V5.1 |
| <a id="sc-20"></a>SC-20 | HTTP Security Headers | `helmet` middleware — `X-Content-Type-Options`, `X-Frame-Options`<br/>_[server.ts:40-50](vscode://file/home/mrohr/juice-shop/server.ts)_ | ⚠️ Partial | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular[F-039](#f-039) — Missing Content Security Policy | ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html), ASVS V14.4 |

_Domain summary: ✅ 0 · ⚠️ 1 · 🔶 1 · ❌ 3 (5 controls total)._

---

### 7.8 Real-time / WebSocket

**Current state:** `Socket.IO` 3 is attached to the same host and port as the REST API. Challenge-verification events (`verifyLocalXssChallenge`, `verifySvgInjectionChallenge`, …) carry client-supplied payloads and have no authentication check on `connect`, no origin validation, and no rate limiting.

**Structural defects:** This is a distinct auth bypass surface — see [§7.3 IAM](#73-identity--access-management) "Shared sink" row. The WS listener never sees the JWT chain that protects the REST API.

**Target architecture:** Apply `io.use(verifyJwt)` middleware that reads `socket.handshake.auth.token` and calls the same verify used by REST routes. Validate `Origin`; reject forged headers.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-25"></a>SC-25 | WebSocket Authentication | `Socket.IO` 3 attached to REST host/port with no JWT check on connect | ❌ Missing | expected: [F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade | ➚ [CWE-306](https://cwe.mitre.org/data/definitions/306.html), ASVS V13.4 |

_Domain summary: ✅ 0 · ⚠️ 0 · 🔶 0 · ❌ 1 (1 control total)._

---

### 7.9 AI / LLM

**Current state:** The chatbot loads its training data from a URL defined in `config/default.yml`. The fetch has no scheme/host allowlist, no integrity hash (SRI-style), and no sandboxed evaluation of the returned content. The `trainingData` URL is mutable at runtime.

**Structural defects:** Two risk classes reachable simultaneously from a single unvalidated URL — **SSRF** (the fetch targets any host including internal/metadata endpoints) and **LLM training-data poisoning** ([F-051](#f-051) — Chatbot trainingData URL fetched without validation

**Target architecture:** Scheme+host allowlist; optional SRI hash pinning; treat the fetched training data as untrusted and validate against a schema before loading.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-26"></a>SC-26 | LLM Training Data Integrity | `chatBot.trainingData` URL loaded from config/default.yml; no allowlist, no integrity hash<br/>_[config/default.yml](vscode://file/home/mrohr/juice-shop/config/default.yml)_ | ❌ Missing | expected: [F-051](#f-051) — Chatbot trainingData URL fetched without validation | ➚ [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) |

_Domain summary: ✅ 0 · ⚠️ 0 · 🔶 0 · ❌ 1 (1 control total)._

---

### 7.10 Audit & Logging

**Current state:** HTTP access logs via `morgan` (and publicly accessible at `/support/logs`!). No structured security-event emission for auth success/failure, role changes, B2B orders, or chatbot interactions. Production error handler returns full stack traces.

**Structural defects:** The attack path is fully untracked — authentication forgeries ([F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts[F-004](#f-004) — JWT alg:none bypass[F-044](#f-044) — B2B orders not audited[F-030](#f-030) — Chatbot admin functions without role check[F-047](#f-047) — Stack traces exposed in error responses

**Target architecture:** Structured security-event log (success/failure/role-change) emitted in OCSF/CEF format; forwarded to a SIEM. Custom production error handler — generic 500 responses with correlation IDs. Move log files out of the web root.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-28"></a>SC-28 | Security Event Logging | No structured auth/security event emission | ❌ Missing | expected: [F-043](#f-043) — Chatbot interactions not logged[F-044](#f-044) — B2B orders not audited[F-048](#f-048) — Authentication events not logged | ➚ [CWE-778](https://cwe.mitre.org/data/definitions/778.html), ASVS V7.2 |
| <a id="sc-30"></a>SC-30 | Production Error Handler | Express default error handler returning full stack traces | ❌ Missing | expected: [F-047](#f-047) — Stack traces exposed in error responses | ➚ [CWE-209](https://cwe.mitre.org/data/definitions/209.html), ASVS V7.4 |
| <a id="sc-29"></a>SC-29 | Log Forwarding / SIEM Integration | No log shipping to a SIEM — logs stay on the `Node.js` host | ❌ Missing | — | ➚ [CWE-778](https://cwe.mitre.org/data/definitions/778.html), ASVS V7.3 |
| <a id="sc-27"></a>SC-27 | Request Access Logging | `morgan` middleware writes access log to stdout (and `/support/logs/`)<br/>_[server.ts:30-35](vscode://file/home/mrohr/juice-shop/server.ts)_ | ⚠️ Partial | [F-032](#f-032) — Application logs served unauthenticated[F-048](#f-048) — Authentication events not logged | ➚ [CWE-778](https://cwe.mitre.org/data/definitions/778.html), ASVS V7.1 |

_Domain summary: ✅ 0 · ⚠️ 1 · 🔶 0 · ❌ 3 (4 controls total)._

---

### 7.11 Infrastructure & Network Segmentation

**Current state:** Single flat network. Management plane (`/ftp`, `/metrics`, `/support/logs`) is co-located with the user API on the same listener. No WAF in the deployment path. No global API rate limiter. Docker uses a floating tag (`FROM node:24`) and `npm install --unsafe-perm`; postinstall hooks run unrestricted.

**Structural defects:** Management endpoints are reachable unauthenticated from the public internet ([F-012](#f-012) — Unauthenticated /ftp directory listing[F-032](#f-032) — Application logs served unauthenticated[F-034](#f-034) — Prometheus /metrics unauthenticated

**Target architecture:** Reverse proxy with WAF (ModSecurity / AWS WAF / Cloudflare) in front of Express. Separate internal listener bound to a private interface for management endpoints. Global rate limit per IP / per token. Pin base image by digest; drop `--unsafe-perm`.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-34"></a>SC-34 | Web Application Firewall | No WAF in deployment path | ❌ Missing | expected: [F-009](#f-009) — SQL injection in product search[F-014](#f-014) — SQL injection in login[F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml() | ASVS V14.1 |
| <a id="sc-35"></a>SC-35 | Network Segmentation | Management plane (`/ftp`, `/metrics`, `/support/logs`) co-located with user API on the same listener | ❌ Missing | expected: [F-012](#f-012) — Unauthenticated /ftp directory listing[F-032](#f-032) — Application logs served unauthenticated[F-034](#f-034) — Prometheus /metrics unauthenticated | ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| <a id="sc-32"></a>SC-32 | API Rate Limiting | No global API rate limiter; only auth endpoints are partially protected | 🔶 Weak | [F-026](#f-026) — YAML bomb (billion laughs) in file upload[F-029](#f-029) — CPU exhaustion DoS via complex expression | ➚ [CWE-400](https://cwe.mitre.org/data/definitions/400.html), ASVS V11.1 |
| <a id="sc-33"></a>SC-33 | Container Hardening | Distroless base image reduces binaries but Dockerfile uses `FROM node:24` (floating tag) and `npm install --unsafe-perm`<br/>_[Dockerfile:1-30](vscode://file/home/mrohr/juice-shop/Dockerfile)_ | ⚠️ Partial | [F-050](#f-050) — Supply-chain / container hygiene | ➚ [CWE-250](https://cwe.mitre.org/data/definitions/250.html), ASVS V14.1 |

_Domain summary: ✅ 0 · ⚠️ 1 · 🔶 1 · ❌ 2 (4 controls total)._

---

### 7.12 Dependency & Supply Chain

**Current state:** Dependabot is enabled for npm but `npm audit` is not a blocking CI gate. `package-lock.json` is committed but postinstall hooks run unrestricted. No SBOM emitted. No container image signing.

**Structural defects:** Unblocked postinstall hooks mean a compromised upstream publisher can execute code at build time. Unsigned images allow substitution of the deployed artifact. These feed directly into [§7.2 Risk #2](#72-key-architectural-risks) (all secrets are in source — build-time RCE exfiltrates everything).

**Target architecture:** Block CI on `npm audit --audit-level=high`. Pin base image by digest (`FROM node@sha256:…`). Disable postinstall scripts (`npm config set ignore-scripts true`). Sign all published images (`cosign`). Emit CycloneDX SBOM on every release.

#### Controls

| ID | Architectural Control | Implementation | Effectiveness | Mitigates | References |
|---- |----------------------- |---------------- |--------------- |----------- |------------ |
| <a id="sc-37"></a>SC-37 | Base Image Pinning | Dockerfile uses `FROM node:24` — floating tag | ❌ Missing | expected: [F-050](#f-050) — Supply-chain / container hygiene | ➚ [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) |
| <a id="sc-39"></a>SC-39 | Container Image Signing | No cosign / Notary signing of published images | ❌ Missing | — | ➚ [CWE-829](https://cwe.mitre.org/data/definitions/829.html), ➚ [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| <a id="sc-36"></a>SC-36 | Dependency Vulnerability Scanning | Dependabot configured for npm; `npm audit` not blocking in CI | 🔶 Weak | [F-010](#f-010) — RCE via notevil sandbox escape | ➚ [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html), ASVS V14.2 |
| <a id="sc-38"></a>SC-38 | Lockfile Integrity | `package-lock.json` committed; Dockerfile uses `npm install --unsafe-perm`, postinstall hooks allowed<br/>_[Dockerfile](vscode://file/home/mrohr/juice-shop/Dockerfile), [package.json](vscode://file/home/mrohr/juice-shop/package.json)_ | 🔶 Weak | [F-050](#f-050) — Supply-chain / container hygiene | ➚ [CWE-506](https://cwe.mitre.org/data/definitions/506.html) |

_Domain summary: ✅ 0 · ⚠️ 0 · 🔶 2 · ❌ 2 (4 controls total)._

---

### 7.13 Secret Management   _(cross-cutting)_

**Current state:** All cryptographic secrets are hardcoded in application source files.
- RSA private key in [lib/insecurity.ts:24](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:24)
- HMAC secret (`pa4qacea4VK9t9nGv7yZtwmj`) in [lib/insecurity.ts:46](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts:46)
- Cookie secret (`kekse`) in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)

**Structural defects:** No secrets manager, no environment-variable loading at startup, no `.env` file pattern, no startup validation. Secrets are exposed in a public GitHub repository.

**Impact:** All secrets must be treated as **permanently compromised**. The RSA private key undermines every authentication control in [§7.3](#73-identity--access-management); the HMAC secret undermines coupon signing; the cookie secret undermines session cookies.

**Target architecture:** Remove all hardcoded secrets. Load from `process.env` with startup assertions that abort when a required secret is missing. Integrate with a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager) for production deployments. Rotate **all** exposed secrets — disclosure history is permanent once pushed to a public repo.

**Primary control:** [SC-04](#sc-04) — Secret Management (❌ Missing).

**Linked findings:**
- [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts
- [F-005](#f-005) — JWT signed with hardcoded key — admin impersonation
- [F-023](#f-023) — Admin panel client-side guard only
- [F-033](#f-033) — Hardcoded HMAC coupon key
- [F-034](#f-034) — Prometheus /metrics unauthenticated

---

### 7.14 Defense-in-Depth Assessment   _(cross-cutting)_

**Current state:** Helmet provides partial security headers (`X-Content-Type-Options`, `X-Frame-Options`). Morgan provides HTTP access logging. Rate limiting applies to 2FA and password reset but not to login. Docker distroless base image.

**Structural defects:** There is **no secondary control at any layer** that would detect or slow down an attacker who has exploited a primary vulnerability. Attacks complete silently with no observable anomalies. The rate-limit key uses spoofable `X-Forwarded-For`. Log files are served publicly. No alerting on authentication anomalies.

**Layered stack (per security layer, present vs. absent controls):**

| Layer | Controls present | Controls missing / weak | Overall |
|------- |------------------ |------------------------- |--------- |
| Perimeter | — | [SC-34](#sc-34) WAF, [SC-35](#sc-35) Segmentation, [SC-17](#sc-17) TLS hardening | ❌ Absent |
| Authentication | [SC-02](#sc-02) Partial, [SC-01](#sc-01) Weak | [SC-31](#sc-31) Weak, [SC-04](#sc-04) Missing, [SC-03](#sc-03) Missing, [SC-05](#sc-05) Weak | 🔶 Weak |
| Authorization | [SC-07](#sc-07) Partial, [SC-09](#sc-09) Partial | [SC-08](#sc-08) Missing | ⚠️ Partial |
| Input validation | [SC-10](#sc-10) Partial, [SC-12](#sc-12) Weak, [SC-15](#sc-15) Adequate | [SC-11](#sc-11), [SC-13](#sc-13), [SC-14](#sc-14) Missing | 🔶 Weak |
| Frontend | [SC-20](#sc-20) Partial, [SC-24](#sc-24) Weak | [SC-21](#sc-21), [SC-22](#sc-22), [SC-23](#sc-23) Missing | 🔶 Weak |
| Logging / Monitoring | [SC-27](#sc-27) Partial | [SC-28](#sc-28), [SC-29](#sc-29), [SC-30](#sc-30) Missing | ❌ Absent |
| Supply chain | [SC-36](#sc-36), [SC-38](#sc-38) Weak | [SC-37](#sc-37), [SC-39](#sc-39) Missing | 🔶 Weak |

**Target architecture:** Add CSP (report-only first, then enforced). Apply rate limiting to all authentication endpoints with a trusted IP source. Move log files out of the web root. Ship structured security events to a SIEM. Introduce a WAF. Separate the management plane onto a private network interface.

**Linked findings:**
- [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()
- [F-039](#f-039) — Missing Content Security Policy
- [F-044](#f-044) — B2B orders not audited
- [F-047](#f-047) — Stack traces exposed in error responses

<!-- QA: F-050 is referenced throughout the document as "Supply-chain / container hygiene" but has no anchor definition in Section 8. The list jumps from F-049 to F-051 in TH-14. F-050 appears to be a legacy consolidated ID that was disaggregated into F-052 through F-059. Either add an anchor row for F-050 as an alias/aggregate, or update all F-050 references to point to the disaggregated IDs (F-052, F-053, F-054). -->

---

## 8. Threat Register

The threat register is structured in two layers: **architectural categories** (TH-01 … TH-18) group findings by the pattern they express; each category expands into the concrete code-level **findings** (F-NNN) that instantiate it. This is the canonical view — executives read the category summary; engineers read the finding table inside the category they own.

**Risk methodology:** Risk = Likelihood × Impact. See Section 8's risk matrix in prior versions for the full conversion table. Each finding row shows the raw CVSS v3.1 base score alongside the qualitative risk rating; category aggregates carry the **max** CVSS and risk of their children.

<!-- QA: Risk Distribution mismatch — this line says Total: 50 (Critical:10/High:25/Medium:15/Low:0) but the threat register contains 57 unique F-NNN anchors (Critical:9/High:33/Medium:13/Low:2). The 7-finding gap may reflect AF-NNN architectural findings not counted, or severity re-labelling due to keystone/contributor role resolution. Reconcile to a single authoritative count. STRIDE sum (8+6+4+19+5+8=50) also does not match 57 total anchors. -->
**Risk Distribution:** Critical: 10 · High: 25 · Medium: 15 · Low: 0 · **Total findings: 50**
**STRIDE Coverage:** Spoofing: 8 · Tampering: 6 · Repudiation: 4 · Information Disclosure: 19 · Denial of Service: 5 · Elevation of Privilege: 8
**Category Distribution:** 16 of 18 categories active — Critical: 7 · High: 8 · Medium: 1 · Low: 0

### 8.A Categories at a glance

Architectural threat categories active in this project, sorted by the **impact-weighted risk score** produced by the triage-validator (Phase 4 `.triage-flags.json` → ranking). Severity column shows effective severity after keystone/contributor role resolution and CWE severity caps. See [§8.C Compound Attack Chains](#8c-compound-attack-chains) for role-scoped chain details.

**Severity legend:**

- 🔴 **Critical** — nominal raw rating OR keystone-role member of an active Critical chain
- 🔴 **Critical** *(raw High)* — elevated from High via keystone role in an active chain
- 🟠 **High** *(raw Medium)* — elevated from Medium via contributor role (capped at High to prevent over-amplification)
- 🟠 **High** / 🟡 **Medium** / 🟢 **Low** — raw rating preserved
- **Breach**: 1 = unauthenticated internet · 2 = authenticated low-privilege user · 3 = requires prior compromise / privileged access

| TH | Category | Severity (eff.) | Findings | Top Finding | Breach | OWASP | Pillar |
|---- |---------- |----------------- |---------- |------------- |-------- |------- |-------- |
| [TH-02](#th-02) | Broken Authentication | 🔴 Critical | 7 | [F-004](#f-004) — JWT alg:none bypass | 1 | ➚ [A07](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| [TH-06](#th-06) | Broken Access Control | 🔴 Critical | 7 | [F-005](#f-005) — JWT signed with hardcoded key — admin impersonation | 1 | ➚ [A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) |
| [TH-01](#th-01) | Injection | 🔴 Critical | 3 | [F-009](#f-009) — SQL injection in product search | 1 | ➚ [A03](https://owasp.org/Top10/A03_2021-Injection/) | ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) |
| [TH-03](#th-03) | Cryptographic Failures | 🔴 Critical | 5 | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts | 2 | ➚ [A02](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| [TH-07](#th-07) | Insecure File Handling | 🔴 Critical | 3 | [F-007](#f-007) — ZIP Slip path traversal in routes/fileUpload.ts | 2 | ➚ [A04](https://owasp.org/Top10/A04_2021-Insecure_Design/) | ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) |
| [TH-04](#th-04) | Insecure Client-Side Storage | 🔴 Critical | 2 | [F-008](#f-008) — JWT stored in localStorage | 2 | ➚ [A02](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) |
| [TH-11](#th-11) | Cross-Site Scripting (XSS) | 🔴 Critical *(raw High)* | 4 | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml() | 1 | ➚ [A03](https://owasp.org/Top10/A03_2021-Injection/) | ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) |
| [TH-05](#th-05) | Code Execution via Unsafe Deserialization or Eval | 🔴 Critical | 1 | [F-010](#f-010) — RCE via notevil sandbox escape | 2 | ➚ [A08](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) | ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) |
| [TH-08](#th-08) | Server-Side Request Forgery | 🔴 Critical *(raw High)* | 2 | [F-051](#f-051) — Chatbot trainingData URL fetched without validation | 2 | ➚ [A10](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) | ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) |
| [TH-14](#th-14) | Supply-Chain Integrity | 🟠 High | 2 | [F-050](#f-050) — Supply-chain / container hygiene | 2 | ➚ [A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) | ➚ [CWE-710](https://cwe.mitre.org/data/definitions/710.html) |
| [TH-12](#th-12) | Denial of Service | 🟠 High | 2 | [F-026](#f-026) — YAML bomb (billion laughs) in file upload | 2 | ➚ [A04](https://owasp.org/Top10/A04_2021-Insecure_Design/) | ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) |
| [TH-15](#th-15) | Cross-Site Request Forgery (CSRF) | 🟠 High | 1 | [F-017](#f-017) — CSRF on password change | 2 | ➚ [A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| [TH-16](#th-16) | Missing Audit Logging & Accountability | 🟠 High | 4 | [F-032](#f-032) — Application logs served unauthenticated | 1 | ➚ [A09](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | ➚ [CWE-710](https://cwe.mitre.org/data/definitions/710.html) |
| [TH-17](#th-17) | Error Information Disclosure | 🟠 High | 4 | [F-013](#f-013) — Full user list accessible to any authenticated user | 1 | ➚ [A05](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ➚ [CWE-710](https://cwe.mitre.org/data/definitions/710.html) |
| [TH-09](#th-09) | Unauthenticated Management Plane | 🟠 High | 2 | [F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade | 1 | ➚ [A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) |
| [TH-18](#th-18) | Open Redirect | 🟡 Medium | 1 | [F-037](#f-037) — Open redirect via to parameter | 1 | ➚ [A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) |


<a id="8b-critical-categories"></a>
### 8.B Critical Categories (6)

#### <a id="th-06"></a>TH-06 — Broken Access Control

> Authorization checks missing, inconsistent, or evaded — IDOR, mass assignment of privileged fields, horizontal/vertical privilege abuse.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-011"></a>F-011 | Mass assignment in user registration | [C-01](#c-01) REST API | 🔴 Critical | 10.0 | [Internet Anon](#vektor-internet-anon) | [M-009](#m-009) — Add field allowlist to User.create()  [CWE-915](https://cwe.mitre.org/data/definitions/915.html) · [API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) |
| <a id="f-005"></a>F-005 | JWT signed with hardcoded RSA key allows admin… | [C-02](#c-02) Auth Service | 🟠 High *(dngr. raw Critical)* | 10.0 | [Internet User](#vektor-internet-user) | [M-001](#m-001) — Rotate all hardcoded secrets[M-004](#m-004) — Enforce server-side admin role on all admin endpoints  [CWE-862](https://cwe.mitre.org/data/definitions/862.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| <a id="f-023"></a>F-023 | Admin panel client-side guard only | [C-03](#c-03) Admin Panel | 🟠 High | 8.3 | [Internet Priv User](#vektor-internet-priv-user) | [M-004](#m-004) — Enforce server-side admin role on all admin endpoints  [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| <a id="f-018"></a>F-018 | IDOR on basket and order endpoints | [C-01](#c-01) REST API | 🟠 High | 8.1 | [Internet User](#vektor-internet-user) | [M-014](#m-014) — Add ownership check to basket and order routes  [CWE-639](https://cwe.mitre.org/data/definitions/639.html) · [API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| <a id="f-030"></a>F-030 | Admin functions without role check | [C-06](#c-06) Chatbot | 🟠 High | 8.1 | [Internet User](#vektor-internet-user) | [M-020](#m-020) — Add admin role check and audit logging to chatbot  [CWE-862](https://cwe.mitre.org/data/definitions/862.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| <a id="f-020"></a>F-020 | Mass update IDOR in reviews | [C-07](#c-07) Product Reviews | 🟠 High | 6.5 | [Internet User](#vektor-internet-user) | [M-015](#m-015) — Fix NoSQL injection and add author binding in reviews  [CWE-639](https://cwe.mitre.org/data/definitions/639.html) · [API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| <a id="f-046"></a>F-046 | Admin user deletion without safeguards | [C-03](#c-03) Admin Panel | 🟡 Medium | — | [Internet User](#vektor-internet-user) | [M-004](#m-004) — Enforce server-side admin role on all admin endpoints  [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |

---

#### <a id="th-05"></a>TH-05 — Code Execution via Unsafe Deserialization or Eval

> User input reaches a deserializer, expression evaluator, or sandbox that executes it as code, enabling server-side RCE.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-010"></a>F-010 | Remote Code Execution via `notevil` sandbox esc… | [C-04](#c-04) B2B Orders | 🔴 Critical | 9.9 | [Internet User](#vektor-internet-user) | [M-008](#m-008) — Replace notevil with static expression parser  [CWE-94](https://cwe.mitre.org/data/definitions/94.html) · [A03:2021](https://owasp.org/Top10/A03_2021-Injection/) |

---

#### <a id="th-07"></a>TH-07 — Insecure File Handling

> File upload, extraction, or path resolution accepts attacker-controlled artifacts (path traversal, dangerous types, ZIP Slip, parser bombs).

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-006"></a>F-006 | XXE via `libxml2` with `noent:true` in `routes/… | [C-05](#c-05) File Upload | 🔴 Critical | 9.9 | [Internet User](#vektor-internet-user) | [M-005](#m-005) — Disable XXE and validate ZIP entry paths  [CWE-611](https://cwe.mitre.org/data/definitions/611.html) · [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| <a id="f-007"></a>F-007 | ZIP Slip path traversal in `routes/fileUpload.ts | [C-05](#c-05) File Upload | 🔴 Critical | 8.8 | [Internet User](#vektor-internet-user) | [M-005](#m-005) — Disable XXE and validate ZIP entry paths  [CWE-22](https://cwe.mitre.org/data/definitions/22.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| <a id="f-028"></a>F-028 | Unrestricted file type upload | [C-05](#c-05) File Upload | 🟠 High | 7.6 | [Internet User](#vektor-internet-user) | [M-005](#m-005) — Disable XXE and validate ZIP entry paths  [CWE-434](https://cwe.mitre.org/data/definitions/434.html) · [A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/) |

---

#### <a id="th-01"></a>TH-01 — Injection

> Untrusted input is executed by data-plane interpreters (SQL, NoSQL, JavaScript sandbox, XML parser, HTML/template) because input neutralization is either absent or bypassed on at least one code path.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-009"></a>F-009 | SQL injection in product search | [C-01](#c-01) REST API | 🔴 Critical | 9.1 | [Internet Anon](#vektor-internet-anon) | [M-007](#m-007) — Parameterize all raw SQL queries  [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · [A03:2021](https://owasp.org/Top10/A03_2021-Injection/) |
| <a id="f-014"></a>F-014 | SQL injection in login | [C-02](#c-02) Auth Service | 🔴 Critical *(raw High)* | 9.1 | [Internet Anon](#vektor-internet-anon) | [M-007](#m-007) — Parameterize all raw SQL queries  [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · [A03:2021](https://owasp.org/Top10/A03_2021-Injection/) |
| <a id="f-019"></a>F-019 | NoSQL injection via `$where` in reviews | [C-07](#c-07) Product Reviews | 🟠 High | 8.3 | [Internet User](#vektor-internet-user) | [M-015](#m-015) — Fix NoSQL injection and add author binding in reviews  [CWE-943](https://cwe.mitre.org/data/definitions/943.html) · [A03:2021](https://owasp.org/Top10/A03_2021-Injection/) |

---

#### <a id="th-08"></a>TH-08 — Server-Side Request Forgery

> Application fetches URLs provided by the user without scheme / host allowlist, enabling internal-network probing, cloud-metadata access, or content-substitution attacks.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-051"></a>F-051 | Chatbot `trainingData` URL fetched without sche… | [C-06](#c-06) Chatbot | 🔴 Critical *(raw Medium)* | 8.2 | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [LLM04:2025](https://genai.owasp.org/llmrisk/llm04-2025-data-and-model-poisoning/) · [A10:2021](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) |
| <a id="f-027"></a>F-027 | SSRF via profile image URL | [C-05](#c-05) File Upload | 🔴 Critical *(raw High)* | 7.7 | [Internet User](#vektor-internet-user) | [M-019](#m-019) — Add URL allowlist for profile image fetch  [CWE-918](https://cwe.mitre.org/data/definitions/918.html) · [A10:2021](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) |

---

#### <a id="th-09"></a>TH-09 — Unauthenticated Management Plane

> Operational or administrative endpoints co-located with the user API but accessible without authentication (metrics, logs, admin panels, internal tools exposed to the public Internet).

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-049"></a>F-049 | Socket | [C-01](#c-01) REST API | 🔴 Critical *(raw High)* | 8.2 | [Internet Anon](#vektor-internet-anon) | [M-027](#m-027) — Authenticate `Socket.IO` WS upgrade and validate Origin  [CWE-306](https://cwe.mitre.org/data/definitions/306.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| <a id="f-012"></a>F-012 | Unauthenticated FTP directory listing at `/ftp/ | [C-01](#c-01) REST API | 🟠 High | 7.5 | [Internet Anon](#vektor-internet-anon) | [M-010](#m-010) — Restrict /ftp and log endpoints  [CWE-548](https://cwe.mitre.org/data/definitions/548.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |

---

### 8.B High Categories (9)

#### <a id="th-02"></a>TH-02 — Broken Authentication

> Authentication mechanisms permit bypass or impersonation — signature verification flaws, weak credential recovery, MFA enforcement gaps, client-side-only guards.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-004"></a>F-004 | JWT `alg:none` bypass | [C-02](#c-02) Auth Service | 🟠 High *(dngr. raw Critical)* | 10.0 | [Internet Anon](#vektor-internet-anon) | [M-003](#m-003) — Pin JWT algorithm to RS256  [CWE-347](https://cwe.mitre.org/data/definitions/347.html) · [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| <a id="f-015"></a>F-015 | Password reset via guessable security answers | [C-02](#c-02) Auth Service | 🟠 High | 9.1 | [Internet Anon](#vektor-internet-anon) | [M-011](#m-011) — Replace security questions with email OTP  [CWE-640](https://cwe.mitre.org/data/definitions/640.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| <a id="f-016"></a>F-016 | 2FA TOTP bypass | [C-02](#c-02) Auth Service | 🟠 High | 7.4 | [Internet User](#vektor-internet-user) | [M-012](#m-012) — Enforce 2FA across all authentication paths  [CWE-287](https://cwe.mitre.org/data/definitions/287.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| <a id="f-021"></a>F-021 | OAuth implicit flow used in frontend | [C-08](#c-08) Frontend SPA | 🟠 High | 5.3 | [Internet User](#vektor-internet-user) | [M-016](#m-016) — Migrate OAuth to PKCE authorization code flow  [CWE-346](https://cwe.mitre.org/data/definitions/346.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| <a id="f-035"></a>F-035 | Auth token revocation absent | [C-02](#c-02) Auth Service | 🟡 Medium | — | [Repo-Read](#vektor-repo-read) / Privileged | [M-023](#m-023) — Add token revocation list and structured auth logging  [CWE-613](https://cwe.mitre.org/data/definitions/613.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| <a id="f-036"></a>F-036 | No rate limiting on auth endpoints | [C-01](#c-01) REST API | 🟡 Medium | — | [Internet Anon](#vektor-internet-anon) | [M-024](#m-024) — Add rate limiting and progressive lockout  [CWE-307](https://cwe.mitre.org/data/definitions/307.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| <a id="f-038"></a>F-038 | No account lockout on failed logins | [C-02](#c-02) Auth Service | 🟡 Medium | — | [Internet Anon](#vektor-internet-anon) | [M-024](#m-024) — Add rate limiting and progressive lockout  [CWE-307](https://cwe.mitre.org/data/definitions/307.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |

---

#### <a id="th-03"></a>TH-03 — Cryptographic Failures

> Cryptographic primitives misused — weak algorithms, hardcoded keys, missing salt, broken randomness, confused responsibilities between auth and storage crypto.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-001"></a>F-001 | RSA private key committed to repository (`lib/i… | [C-02](#c-02) Auth Service | 🟠 High *(dngr. raw Critical)* | 10.0 | [Repo-Read](#vektor-repo-read) | [M-001](#m-001) — Rotate all hardcoded secrets  [CWE-798](https://cwe.mitre.org/data/definitions/798.html) · [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| <a id="f-002"></a>F-002 | Password hashing uses MD5 without salt (`lib/in… | [C-02](#c-02) Auth Service | 🟠 High *(dngr. raw Critical)* | 9.1 | [Repo-Read](#vektor-repo-read) / Privileged | [M-002](#m-002) — Replace MD5 with bcrypt  [CWE-916](https://cwe.mitre.org/data/definitions/916.html) · [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| <a id="f-022"></a>F-022 | OAuth predictable password | [C-08](#c-08) Frontend SPA | 🟠 High | 9.1 | [Repo-Read](#vektor-repo-read) / Privileged | [M-002](#m-002) — Replace MD5 with bcrypt  [CWE-916](https://cwe.mitre.org/data/definitions/916.html) · [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| <a id="f-033"></a>F-033 | Coupon code uses hardcoded HMAC key | [C-01](#c-01) REST API | 🟠 High | 5.3 | [Repo-Read](#vektor-repo-read) | [M-001](#m-001) — Rotate all hardcoded secrets  [CWE-321](https://cwe.mitre.org/data/definitions/321.html) · [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| <a id="f-045"></a>F-045 | OAuth implicit flow token in URL fragment | [C-02](#c-02) Auth Service | 🟡 Medium | — | [Internet User](#vektor-internet-user) | [M-016](#m-016) — Migrate OAuth to PKCE authorization code flow  [CWE-346](https://cwe.mitre.org/data/definitions/346.html) · [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |

---

#### <a id="th-04"></a>TH-04 — Insecure Client-Side Storage

> Session tokens or sensitive data stored in browser-accessible locations (localStorage, sessionStorage, non-HttpOnly cookies) exposing them to XSS exfiltration.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-008"></a>F-008 | JWT stored in `localStorage` (`frontend/src/app… | [C-08](#c-08) Frontend SPA | 🟠 High *(dngr. raw Critical)* | 9.3 | [Internet User](#vektor-internet-user) | [M-006](#m-006) — Move JWT from localStorage to HttpOnly cookie  [CWE-922](https://cwe.mitre.org/data/definitions/922.html) · [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| <a id="f-040"></a>F-040 | Sensitive data in `localStorage | [C-08](#c-08) Frontend SPA | 🟠 High *(raw Medium)* | — | [Internet User](#vektor-internet-user) | [M-006](#m-006) — Move JWT from localStorage to HttpOnly cookie  [CWE-922](https://cwe.mitre.org/data/definitions/922.html) · [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |

---

#### <a id="th-14"></a>TH-14 — Supply-Chain Integrity

> Build-time artifacts (base images, dependencies, CI actions, training data) accepted from sources without provenance verification, enabling substitution attacks and transitive code execution at build time.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-056"></a>F-056 | 12 of 14 GitHub Actions workflows have no expli… | [C-01](#c-01) REST API | 🟠 High | 7.3 | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) · [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| <a id="f-054"></a>F-054 | package.json` defines a postinstall hook that r… | [C-01](#c-01) REST API | 🟠 High *(raw Medium)* | — | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) · [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| <a id="f-052"></a>F-052 | Dockerfile base image uses floating tag `FROM n… | [C-01](#c-01) REST API | 🟡 Medium | 5.9 | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) · [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| <a id="f-041"></a>F-041 | Reviews not bound to verified identity | [C-07](#c-07) Product Reviews | 🟡 Medium | — | [Build-Time](#vektor-build-time) | [M-015](#m-015) — Fix NoSQL injection and add author binding in reviews  [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| <a id="f-053"></a>F-053 | Dockerfile runs `npm install --omit=dev --unsaf… | [C-01](#c-01) REST API | 🟡 Medium | — | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) · [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| <a id="f-057"></a>F-057 | No `.github/dependabot.yml` and no `renovate.js… | [C-01](#c-01) REST API | 🟡 Medium | — | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) · [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| <a id="f-058"></a>F-058 | Release workflow (`release.yml`) pushes Docker… | [C-01](#c-01) REST API | 🟡 Medium | — | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) · [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| <a id="f-055"></a>F-055 | .github/workflows/zap_scan.yml` pins `actions/c… | [C-01](#c-01) REST API | 🟢 Low | — | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data  [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) · [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| <a id="f-059"></a>F-059 | Dockerfile lacks `HEALTHCHECK` instruction | [C-01](#c-01) REST API | 🟢 Low | — | [Build-Time](#vektor-build-time) | [M-028](#m-028) — Pin container base images and lock down training data |

---

#### <a id="th-16"></a>TH-16 — Missing Audit Logging & Accountability

> Security-relevant events (authentication, authorization decisions, admin actions, data mutations) are not recorded in an append-only security log, preventing forensic reconstruction.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-032"></a>F-032 | Logs served unauthenticated | [C-01](#c-01) REST API | 🟠 High | 7.5 | [Internet Anon](#vektor-internet-anon) | [M-010](#m-010) — Restrict /ftp and log endpoints  [CWE-532](https://cwe.mitre.org/data/definitions/532.html) · [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) |
| <a id="f-043"></a>F-043 | Chatbot interactions not logged | [C-06](#c-06) Chatbot | 🟠 High *(raw Medium)* | — | [Repo-Read](#vektor-repo-read) / Privileged | [M-020](#m-020) — Add admin role check and audit logging to chatbot  [CWE-778](https://cwe.mitre.org/data/definitions/778.html) · [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) |
| <a id="f-044"></a>F-044 | B2B orders not audited | [C-04](#c-04) B2B Orders | 🟠 High *(raw Medium)* | — | [Repo-Read](#vektor-repo-read) / Privileged | [M-008](#m-008) — Replace notevil with static expression parser  [CWE-778](https://cwe.mitre.org/data/definitions/778.html) · [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) |
| <a id="f-048"></a>F-048 | Authentication events not logged | [C-02](#c-02) Auth Service | 🟠 High *(raw Medium)* | — | [Internet Anon](#vektor-internet-anon) | [M-023](#m-023) — Add token revocation list and structured auth logging  [CWE-778](https://cwe.mitre.org/data/definitions/778.html) · [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) |

---

#### <a id="th-12"></a>TH-12 — Denial of Service

> Endpoints consume unbounded resources — no rate limiting, no account lockout, unbounded expression evaluation, unbounded file parsing.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-026"></a>F-026 | YAML bomb (billion laughs) | [C-05](#c-05) File Upload | 🟠 High | 6.5 | [Internet User](#vektor-internet-user) | [M-018](#m-018) — Disable YAML entity expansion in file upload  [CWE-400](https://cwe.mitre.org/data/definitions/400.html) · [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| <a id="f-029"></a>F-029 | CPU exhaustion DoS via complex expression | [C-04](#c-04) B2B Orders | 🟠 High | 6.5 | [Internet User](#vektor-internet-user) | [M-008](#m-008) — Replace notevil with static expression parser  [CWE-400](https://cwe.mitre.org/data/definitions/400.html) · [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |

---

#### <a id="th-15"></a>TH-15 — Cross-Site Request Forgery (CSRF)

> State-changing endpoints accept authenticated cross-origin requests without CSRF token or SameSite-cookie enforcement, enabling attacker pages to perform actions on behalf of victims.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-017"></a>F-017 | CSRF on password change | [C-02](#c-02) Auth Service | 🟠 High | 6.5 | [Victim-Required](#vektor-victim-required) | [M-013](#m-013) — Add CSRF protection to state-changing endpoints  [CWE-352](https://cwe.mitre.org/data/definitions/352.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |

---

#### <a id="th-17"></a>TH-17 — Error Information Disclosure

> Unhandled errors return stack traces, library versions, file paths, or internal state to untrusted callers, aiding reconnaissance.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-013"></a>F-013 | Full user list accessible to any authenticated… | [C-03](#c-03) Admin Panel | 🟠 High | 6.5 | [Internet Priv User](#vektor-internet-priv-user) | [M-004](#m-004) — Enforce server-side admin role on all admin endpoints  [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| <a id="f-034"></a>F-034 | Prometheus metrics unauthenticated | [C-03](#c-03) Admin Panel | 🟠 High | 5.3 | [Internet Anon](#vektor-internet-anon) | [M-022](#m-022) — Restrict /metrics to internal networks  [CWE-306](https://cwe.mitre.org/data/definitions/306.html) · [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| <a id="f-042"></a>F-042 | User data leakage via username injection | [C-06](#c-06) Chatbot | 🟡 Medium | — | [Internet User](#vektor-internet-user) | [M-020](#m-020) — Add admin role check and audit logging to chatbot  [CWE-201](https://cwe.mitre.org/data/definitions/201.html) · [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) |
| <a id="f-047"></a>F-047 | Stack traces exposed in error responses | [C-01](#c-01) REST API | 🟡 Medium | — | [Internet Anon](#vektor-internet-anon) | [M-009](#m-009) — Add field allowlist to User.create()  [CWE-209](https://cwe.mitre.org/data/definitions/209.html) · [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |

---

#### <a id="th-11"></a>TH-11 — Cross-Site Scripting (XSS)

> Attacker-controlled input reaches the rendered DOM without proper escaping — stored, reflected, or DOM-based XSS. Especially impactful when combined with client-side JWT storage and missing CSP.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-024"></a>F-024 | XSS via `DomSanitizer.bypassSecurityTrustHtml() | [C-08](#c-08) Frontend SPA | 🟠 High | 5.4 | [Victim-Required](#vektor-victim-required) | [M-017](#m-017) — Remove DomSanitizer bypasses and innerHTML assignments  [CWE-79](https://cwe.mitre.org/data/definitions/79.html) · [A03:2021](https://owasp.org/Top10/A03_2021-Injection/) |
| <a id="f-025"></a>F-025 | DOM XSS via `innerHTML` assignments in Angular… | [C-08](#c-08) Frontend SPA | 🟠 High | 5.4 | [Victim-Required](#vektor-victim-required) | [M-017](#m-017) — Remove DomSanitizer bypasses and innerHTML assignments  [CWE-79](https://cwe.mitre.org/data/definitions/79.html) · [A03:2021](https://owasp.org/Top10/A03_2021-Injection/) |
| <a id="f-031"></a>F-031 | CORS wildcard | [C-01](#c-01) REST API | 🟠 High | 5.3 | [Internet Anon](#vektor-internet-anon) | [M-021](#m-021) — Restrict CORS to allowed origins  [CWE-942](https://cwe.mitre.org/data/definitions/942.html) · [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| <a id="f-039"></a>F-039 | Missing Content Security Policy | [C-08](#c-08) Frontend SPA | 🟠 High *(raw Medium)* | — | [Internet User](#vektor-internet-user) | [M-026](#m-026) — Implement Content Security Policy  [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |

---

### 8.B Medium Categories (1)

#### <a id="th-18"></a>TH-18 — Open Redirect

> Redirect endpoints accept attacker-controlled destinations without allowlisting, enabling phishing and OAuth state-token exfiltration.

**Findings in this category:**

| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |
|---- |--------- |----------- |------------- |------ |-------- |------------ |------------ |
| <a id="f-037"></a>F-037 | Open redirect | [C-01](#c-01) REST API | 🟡 Medium | — | [Victim-Required](#vektor-victim-required) | [M-025](#m-025) — Allowlist redirect destinations |

---

### 8.C Compound Attack Chains

Juice Shop exhibits **6 recognised compound attack chains** — combinations of findings that, in aggregate, pose elevated architectural risk. Each chain distinguishes **keystone** findings (the direct exploit vector, whose effective severity rises to the chain severity) from **contributor** findings (amplifiers / defense-in-depth failures, capped at High so they cannot individually inherit Critical via chain membership).

#### <a id="cc-01"></a>CC-01 — Stored XSS → Session Theft via localStorage JWT

| | |
|--- |--- |
| **Compound severity** | 🔴 Critical |
| **Severity justification** | A stored XSS payload (keystone) CAN exfiltrate the session token in a single request — the attack is one-step, requires no additional attacker privilege, and affects every user who views the infected content. This is distinct from the contributors (missing CSP, PII in localStorage) which amplify the damage but do not individually realise it. |
| **Breach distance** | 2 (auth user) |
| **Keystones** *(effective Critical)* | [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()<br/>[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular |
| **Contributors** *(capped at High)* | [F-008](#f-008) — JWT stored in localStorage<br/>[F-039](#f-039) — Missing Content Security Policy<br/>[F-040](#f-040) — Sensitive data in localStorage |
| **Mitigates by breaking** | Move JWT from localStorage to HttpOnly cookie (removes chain by severing exfil target) · Implement Content Security Policy (reduces chain viability) · Remove DomSanitizer.bypassSecurityTrustHtml calls (removes the keystone) |

**Keystone:** Stored/reflected XSS payloads (F-024, F-025) inject
attacker-controlled script into a rendered page. A single payload is
sufficient to execute arbitrary JavaScript in every visitor's browser.

**Contributors (amplifiers, not individually Critical):** The JWT is
stored in `localStorage` (F-008, F-040) — the XSS payload can read
and exfiltrate it with no CSP to block the outbound request
(F-039). Fixing any ONE of the three layers reduces the chain's
severity; fixing all three closes it.

---

#### <a id="cc-03"></a>CC-03 — SQL Injection → Credential Dump → Offline Hash Cracking

| | |
|--- |--- |
| **Compound severity** | 🔴 Critical |
| **Severity justification** | The keystone is the SQL injection itself — it is directly exploitable against an unauthenticated endpoint and yields immediate DB dump. The weak password hashing (CWE-916) converts the dump into plaintext credentials in minutes on commodity hardware. The SQLi alone is already Critical; the hashing weakness is a severity amplifier that reduces time-to-impact from hours-of-offline-work to minutes. |
| **Breach distance** | 1 (internet) |
| **Keystones** *(effective Critical)* | [F-009](#f-009) — SQL injection in product search<br/>[F-014](#f-014) — SQL injection in login<br/>[F-019](#f-019) — NoSQL injection via $where in reviews |
| **Contributors** *(capped at High)* | [F-002](#f-002) — Password hashing uses MD5 without salt<br/>[F-022](#f-022) — OAuth predictable password derived as MD5(email) |
| **Mitigates by breaking** | Parameterize raw SQL queries (removes keystone, closes chain) · Migrate password hashing to bcrypt / argon2 (neutralises contributor) |

**Keystone:** Unauthenticated SQL injection (F-009, F-014) dumps the
user credential table in a single request.

**Contributor:** Weak password hashing (F-002, F-022) reduces brute
force to minutes on commodity GPUs. Without the hashing weakness the
chain still succeeds (SQLi alone is Critical) but recovery of plaintext
passwords takes longer. Fixing only the hashing does NOT close the chain.

---

#### <a id="cc-02"></a>CC-02 — Hardcoded Crypto Key → Offline Token Forgery

| | |
|--- |--- |
| **Compound severity** | 🔴 Critical |
| **Severity justification** | The keystone is the presence of the RSA private key in public source — this alone enables JWT forgery for any claim. The signature-verification bypass (alg:none) is a redundant attack path: with the hardcoded key the attacker does not need alg:none, and vice versa. Both are keystones because either alone realises the chain. |
| **Breach distance** | 1 (internet) |
| **Keystones** *(effective Critical)* | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts<br/>[F-004](#f-004) — JWT alg:none bypass<br/>[F-005](#f-005) — JWT signed with hardcoded key — admin impersonation<br/>[F-033](#f-033) — Hardcoded HMAC coupon key |
| **Mitigates by breaking** | Rotate hardcoded secrets and load from env vars (removes CWE-321 keystone) · Pin JWT algorithm and upgrade verification library (removes CWE-347 keystone) |

**Keystone (either realises the chain alone):** The RSA private key baked
into `lib/insecurity.ts` (F-001, F-033) is recoverable by any attacker
reading the repository. The signature-verification path (F-004)
accepts `alg:none`, a second independent bypass. Either keystone alone
yields JWT forgery for any identity, including admin.

---

#### <a id="cc-06"></a>CC-06 — Mass Assignment → Self-Promotion to Admin

| | |
|--- |--- |
| **Compound severity** | 🔴 Critical |
| **Severity justification** | Mass assignment alone creates a privilege-escalation vector (user can self-assign privileged fields). When combined with missing admin-role enforcement on subsequent endpoints, the escalation becomes full admin takeover via one POST to /api/Users. Both findings are keystones because either alone is Critical in this architecture. |
| **Breach distance** | 1 (internet) |
| **Keystones** *(effective Critical)* | [F-005](#f-005) — JWT signed with hardcoded key — admin impersonation<br/>[F-011](#f-011) — Mass assignment in user registration<br/>[F-023](#f-023) — Admin panel client-side guard only<br/>[F-030](#f-030) — Chatbot admin functions without role check |
| **Mitigates by breaking** | Field allowlist on User.create() (removes CWE-915 keystone) · Server-side admin role enforcement (removes CWE-285/CWE-862 keystone) |

**Keystone (each alone realises the chain):** The registration endpoint
(F-011) accepts a `role` field in the request body. The missing
server-side admin-role guard on privileged routes (F-005, F-023, F-030)
means a user with `role: admin` in their JWT is accepted — no further
validation. A single anonymous POST to create a user with `role=admin`
yields full admin access. Fix either keystone to close the chain.

---

#### <a id="cc-04"></a>CC-04 — SSRF → Cloud Metadata Service

| | |
|--- |--- |
| **Compound severity** | 🔴 Critical |
| **Severity justification** | The SSRF is the keystone — without it, no outbound request is possible. Critical severity is conditional on cloud deployment: on-prem deployments with no metadata service have the SSRF but not the chain. The chain severity therefore describes the *realised* Critical case; in cloud-less deployments the raw SSRF severity (High) applies. |
| **Breach distance** | 2 (auth user) |
| **Keystones** *(effective Critical)* | [F-027](#f-027) — SSRF via profile image URL<br/>[F-051](#f-051) — Chatbot trainingData URL fetched without validation |
| **Mitigates by breaking** | Add URL allowlist for server-side fetches (removes keystone) · Block RFC-1918 and metadata-service IPs at egress (breaks chain even with SSRF) |

**Keystone:** Server-side URL fetches (F-027, F-051) accept attacker-
controlled destinations without scheme/host allowlist. On cloud-hosted
deployments the attacker targets `http://169.254.169.254/` (AWS),
`metadata.google.internal` (GCP), or the Azure IMDS endpoint to retrieve
IAM credentials with the workload's role. Exploit viability depends on
runtime environment.

---

#### <a id="cc-05"></a>CC-05 — Unauthenticated Management Plane → Reconnaissance

| | |
|--- |--- |
| **Compound severity** | 🟠 High |
| **Severity justification** | Reconnaissance alone is not Critical. The chain is High because each member yields a distinct category of passive information (filenames, stack traces, runtime metrics, log snippets) and together they paint a complete architectural picture that enables SUBSEQUENT targeted attacks. The chain becomes Critical only when a specific listed artifact contains a high-value secret (e.g. .env in /ftp with database URL) — which would be a separate finding under TH-03 Cryptographic Failures, not under this chain. |
| **Breach distance** | 1 (internet) |
| **Contributors** *(capped at High)* | [F-012](#f-012) — Unauthenticated /ftp directory listing<br/>[F-032](#f-032) — Application logs served unauthenticated<br/>[F-043](#f-043) — Chatbot interactions not logged<br/>[F-044](#f-044) — B2B orders not audited<br/>[F-048](#f-048) — Authentication events not logged<br/>[F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade |
| **Mitigates by breaking** | Authenticate /ftp and /support/logs (removes CWE-548 / CWE-532) · Restrict /metrics to internal networks (removes CWE-306 instance) · Authenticate `Socket.IO` WS upgrade (removes CWE-306 instance) |

**Reconnaissance amplifier** (High, not Critical): Multiple management
endpoints (F-012, F-032, F-043, F-044, F-048, F-049) are anonymously reachable on the same listener
as the user API. Each yields a distinct reconnaissance category
(filesystem listing, runtime metrics, application logs, challenge state).
The value for an attacker is targeting precision for subsequent exploits,
not direct data extraction. Fix the unauthenticated-reachability gap at
deployment level (reverse-proxy path rules) or at application level
(add auth middleware).

---

<a id="8d-architectural-findings"></a>
### 8.D Architectural Findings

Beyond concrete code/config findings, 7 **systemic architectural weaknesses** were identified. Each aggregates multiple code-level findings and points to the underlying design defect. These cannot be patched — they require architectural rework (service decomposition, vault integration, network segmentation, etc.).

#### <a id="af-001"></a>AF-001 — Monolithic process boundary — no component isolation

> Authentication, business logic, file upload handling, B2B code execution, chatbot, and WebSocket all share one `Node.js` process. An RCE (F-010) or XXE (F-006) in any handler compromises all other components sharing the same memory space and filesystem.

| | |
|--- |--- |
| **Architectural theme** | Separation |
| **Severity** | 🟠 High |
| **Impact** | High |
| **Structural defect** | No process or network isolation between security-sensitive components |
| **Target architecture** | Decompose by security boundary: auth service, file handler, B2B evaluator as separate services with minimal trust |
| **Remediation effort** | High |
| **Aggregates findings** | [F-010](#f-010) — RCE via notevil sandbox escape[F-006](#f-006) — XXE via libxml2 with noent:true[F-007](#f-007) — ZIP Slip path traversal in routes/fileUpload.ts[F-037](#f-037) — Open redirect via to parameter |
| **Primary mitigations** | [M-008](#m-008) — Replace notevil with static expression parser[M-005](#m-005) — Disable XXE and validate ZIP entry paths |
| **Derived from** | [§7.2](#72-key-architectural-risks) row 1 — Monolith with no separation |

---

#### <a id="af-002"></a>AF-002 — All secrets embedded in source code

> RSA private key, HMAC secret, cookie secret, and OAuth client secret are all hardcoded in the public GitHub repository. No secrets manager or env-var loader pattern exists. The secrets must be treated as permanently compromised and rotated.

| | |
|--- |--- |
| **Architectural theme** | SecretManagement |
| **Severity** | 🟠 High |
| **Impact** | Critical |
| **Structural defect** | No secrets manager integration, no environment-variable loader at startup, no rotation procedure |
| **Target architecture** | Load all secrets from vault/KMS/parameter-store at startup, fail-fast on missing values, automated rotation |
| **Remediation effort** | Medium |
| **Aggregates findings** | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts[F-033](#f-033) — Hardcoded HMAC coupon key |
| **Primary mitigations** | [M-001](#m-001) — Rotate all hardcoded secrets |
| **Derived from** | [§7.2](#72-key-architectural-risks) row 2 + [§7.13 Secret Management](#713-secret-management) |

---

#### <a id="af-003"></a>AF-003 — Unsafe code execution pattern — user input reaches eval-equivalent

> User-supplied strings are passed through notevil + vm.createContext() for B2B order expressions. No input sanitization scheme can make eval() of untrusted input safe — the architectural choice to evaluate user expressions is the root defect.

| | |
|--- |--- |
| **Architectural theme** | InputValidation |
| **Severity** | 🟠 High |
| **Impact** | Critical |
| **Structural defect** | Dynamic code evaluation on untrusted input |
| **Target architecture** | Replace expression evaluation with declarative schema validation (zod/joi) + typed parser that accepts only a closed grammar |
| **Remediation effort** | High |
| **Aggregates findings** | [F-010](#f-010) — RCE via notevil sandbox escape[F-030](#f-030) — Chatbot admin functions without role check |
| **Primary mitigations** | [M-008](#m-008) — Replace notevil with static expression parser |
| **Derived from** | [§7.2](#72-key-architectural-risks) row 3 — Unsafe code execution pattern |

---

#### <a id="af-004"></a>AF-004 — Unauthenticated management plane co-located with user API

> Management endpoints (`/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics`, `/api-docs`) are served on the same host/port as the user-facing REST API without any authentication layer. An internet attacker gains a complete operational picture before attempting any exploit.

| | |
|--- |--- |
| **Architectural theme** | AttackSurfaceDesign |
| **Severity** | 🟠 High |
| **Impact** | High |
| **Structural defect** | No network segmentation between user plane and operations plane; no reverse-proxy path rules separating them |
| **Target architecture** | Bind management endpoints to a separate listener on 127.0.0.1 or a private subnet; front with admin-only auth middleware |
| **Remediation effort** | Medium |
| **Aggregates findings** | [F-012](#f-012) — Unauthenticated /ftp directory listing[F-032](#f-032) — Application logs served unauthenticated[F-034](#f-034) — Prometheus /metrics unauthenticated[F-042](#f-042) — User data leakage via username injection |
| **Primary mitigations** | [M-010](#m-010) — Restrict /ftp and log endpoints[M-022](#m-022) — Restrict /metrics to internal networks |
| **Derived from** | [§7.2](#72-key-architectural-risks) row 4 — Unauthenticated management plane |

---

#### <a id="af-005"></a>AF-005 — Browser-resident session material — JWT in localStorage

> JWT tokens stored in localStorage are accessible to any same-origin script. Combined with DomSanitizer-bypass XSS (F-024) and missing CSP (F-039), any XSS payload yields direct session takeover.

| | |
|--- |--- |
| **Architectural theme** | SessionDesign |
| **Severity** | 🟠 High |
| **Impact** | High |
| **Structural defect** | Wrong storage layer for high-security session tokens |
| **Target architecture** | HttpOnly, Secure, SameSite=Strict cookie for session material; localStorage only for non-sensitive UI state |
| **Remediation effort** | Medium |
| **Aggregates findings** | [F-008](#f-008) — JWT stored in localStorage[F-040](#f-040) — Sensitive data in localStorage[F-045](#f-045) — OAuth implicit flow token in URL fragment |
| **Primary mitigations** | [M-006](#m-006) — Move JWT from localStorage to HttpOnly cookie |
| **Derived from** | [§7.2](#72-key-architectural-risks) row 5 — Browser-resident session material |

---

#### <a id="af-006"></a>AF-006 — No defense-in-depth at browser layer (CSP, HSTS, CORS, WAF all absent or misconfigured)

> No Content Security Policy, no HSTS, no Permissions-Policy, CORS set to wildcard with credentials, no WAF in deployment path. Each missing layer amplifies the blast radius of XSS and CSRF attacks.

| | |
|--- |--- |
| **Architectural theme** | DefenseInDepth |
| **Severity** | 🟡 Medium |
| **Impact** | Medium |
| **Structural defect** | Missing multiple layered browser-security controls |
| **Target architecture** | Baseline security headers via helmet (CSP, HSTS, Permissions-Policy, X-Frame-Options), strict CORS allowlist, WAF for pattern filtering |
| **Remediation effort** | Medium |
| **Aggregates findings** | [F-039](#f-039) — Missing Content Security Policy[F-031](#f-031) — CORS wildcard Access-Control-Allow-Origin: * |
| **Primary mitigations** | [M-026](#m-026) — Implement Content Security Policy[M-021](#m-021) — Restrict CORS to allowed origins |
| **Derived from** | [§7.14 Defense-in-Depth Assessment](#714-defense-in-depth-assessment) |

---

#### <a id="af-007"></a>AF-007 — No supply-chain integrity controls in build pipeline

> Dockerfile uses floating `FROM node:24` tag without digest pin; npm install runs with --unsafe-perm and without --ignore-scripts; postinstall hooks execute with elevated privileges; GitHub Actions pinned to mutable tags. Any compromised upstream publisher gains build-time RCE.

| | |
|--- |--- |
| **Architectural theme** | SupplyChain |
| **Severity** | 🟠 High |
| **Impact** | Critical |
| **Structural defect** | Build pipeline trusts every transitive publisher without verification |
| **Target architecture** | Digest-pin base images, npm ci --ignore-scripts, SHA-pinned GitHub Actions, SBOM generation, cosign-signed release images |
| **Remediation effort** | Medium |
| **Aggregates findings** | [F-050](#f-050) — Supply-chain / container hygiene |
| **Primary mitigations** | [M-028](#m-028) — Pin container base images and lock down training data |
| **Derived from** | [§7.13 Secret Management](#713-secret-management) + recon-summary §7.14-7.17 |

---

## 9. Mitigation Register

Mitigations are grouped by rollout priority. Within each priority group, entries are ordered by effort (lowest first), then by number of threats addressed (highest first).

### P1 — Immediate

These mitigations address Critical-severity threats or compound vulnerabilities with active exploitation potential. They should be completed before the next release.

---

#### <a id="m-001"></a>M-001 — Rotate all hardcoded secrets (RSA key, HMAC coupon key)

**Addresses:**
- [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts
- [F-005](#f-005) — JWT signed with hardcoded key — admin impersonation
- [F-033](#f-033) — Hardcoded HMAC coupon key

**Prevents CWEs:**

- ➚ [CWE-321](https://cwe.mitre.org/data/definitions/321.html) — Use of Hard-coded Cryptographic Key
- ➚ [CWE-285](https://cwe.mitre.org/data/definitions/285.html) — Improper Authorization

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Low

**Why:** The RSA private key in `lib/insecurity.ts` is the root-cause vulnerability for the entire authentication bypass chain. Rotating it and loading it from environment variables immediately invalidates all forged tokens and coupon codes. This is the single highest-leverage fix in the entire codebase.

**How:**
1. Generate a new RSA key pair: `openssl genrsa -out jwt_private.pem 2048 && openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem`
2. Store the private key in an environment variable: `JWT_PRIVATE_KEY` (base64-encoded PEM)
3. Remove the hardcoded key from [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts) and load via `Buffer.from(process.env.JWT_PRIVATE_KEY, 'base64').toString()`
4. Repeat for the coupon HMAC key: `COUPON_HMAC_KEY` env var
5. Add both variables to `.env.example` and CI secret store; add to `.gitignore`

```javascript
// Before (lib/insecurity.ts):
const privateKey = `-----BEGIN RSA PRIVATE KEY-----\nMIIE...`

// After:
const privateKey = Buffer.from(process.env.JWT_PRIVATE_KEY ?? '', 'base64').toString('utf8')
if (\!privateKey) throw new Error('JWT_PRIVATE_KEY environment variable is required')
```

**Verification:** Clone the repo on a clean machine, set a different `JWT_PRIVATE_KEY`, then attempt to use a JWT forged with the old key — confirm 401 is returned. Confirm `git log --all -S 'BEGIN RSA PRIVATE KEY'` returns no matches.

**Reference:** ➚ [CWE-321](https://cwe.mitre.org/data/definitions/321.html) Pillar ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · OWASP ➚ [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

#### <a id="m-002"></a>M-002 — Replace MD5 password hashing with bcrypt

**Addresses:**
- [F-002](#f-002) — Password hashing uses MD5 without salt
- [F-022](#f-022) — OAuth predictable password derived as MD5(email)

**Prevents CWEs:** ➚ [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — Use of Password Hash with Insufficient Computational Effort

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Low

**Why:** MD5 hashes are instantly crackable with freely available rainbow tables. All existing user passwords are effectively compromised. Bcrypt with cost factor 12 adds ~300ms per hash and renders brute force impractical.

**How:**
1. Install bcrypt: `npm install bcryptjs`
2. Replace `crypto.createHash('md5').update(password).digest('hex')` with `bcrypt.hashSync(password, 12)` in [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts)
3. Update login comparison to use `bcrypt.compareSync(candidatePassword, storedHash)`
4. Write a one-time migration script to re-hash existing passwords on next login (detect MD5-length hashes and re-hash on successful auth)
5. Replace the OAuth predictable password `hash(email)` with a cryptographically random 32-byte token

```javascript
// Before:
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// After:
import bcrypt from 'bcryptjs'
export const hash = (data: string) => bcrypt.hashSync(data, 12)
export const verify = (candidate: string, stored: string) => bcrypt.compareSync(candidate, stored)
```

**Verification:** Register a new user, inspect the database — confirm the stored hash is 60 characters (bcrypt format), not 32 characters (MD5). Confirm login still works with the correct password and fails with a wrong password.

**Reference:** ➚ [CWE-916](https://cwe.mitre.org/data/definitions/916.html) Pillar ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · OWASP ➚ [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

#### <a id="m-003"></a>M-003 — Pin JWT algorithm to RS256

**Addresses:** [F-004](#f-004) — JWT alg:none bypass

**Prevents CWEs:** ➚ [CWE-347](https://cwe.mitre.org/data/definitions/347.html) — Improper Verification of Cryptographic Signature

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Low

**Why:** The `alg:none` bypass is a one-line fix. Failing to pin the algorithm means any attacker can forge tokens by stripping the signature — no key access required.

**How:**
1. In [lib/insecurity.ts](vscode://file/home/mrohr/juice-shop/lib/insecurity.ts), pass `{ algorithms: ['RS256'] }` as the second argument to `jwt.verify()`
2. Ensure `jwt.sign()` always specifies `{ algorithm: 'RS256' }`
3. Reject any token whose header `alg` field is not `RS256`

```javascript
// Before:
jwt.verify(token, publicKey)

// After:
jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

**Verification:** Craft a token with `alg: none` and an empty signature. Send it to any authenticated endpoint — confirm 401 is returned.

**Reference:** ➚ [CWE-347](https://cwe.mitre.org/data/definitions/347.html) Pillar ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · OWASP ➚ [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

---

#### <a id="m-004"></a>M-004 — Enforce server-side admin role on all admin endpoints

**Addresses:**
- [F-005](#f-005) — JWT signed with hardcoded key — admin impersonation
- [F-013](#f-013) — Full user list accessible to any authenticated user
- [F-023](#f-023) — Admin panel client-side guard only
- [F-046](#f-046) — Admin user deletion without safeguards

**Prevents CWEs:**

- ➚ [CWE-285](https://cwe.mitre.org/data/definitions/285.html) — Improper Authorization
- ➚ [CWE-200](https://cwe.mitre.org/data/definitions/200.html) — Exposure of Sensitive Information to an Unauthorized Actor
- ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) — Improper Access Control

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Medium

**Why:** Client-side route guards are not security controls. Any forged JWT (trivial with the hardcoded key) bypasses the Angular guard entirely. All admin-only APIs must independently verify the role server-side.

**How:**
1. Audit every route called by the admin panel Angular component (`/api/Users`, `/api/Complaints`, `/api/Feedbacks`, and `/administration` static route)
2. Add `ensureAdminRole` middleware to each: `router.get('/api/Users', security.isAuthorized(), ensureAdminRole, usersController.list)`
3. For the admin panel SPA route, add a server-side redirect check — serve a 403 page if the JWT role is not admin
4. Add soft-delete to user deletion: `User.update({ deletedAt: new Date() }, { where: { id } })` instead of `User.destroy()`
5. Add rate limiting (max 10 deletions per minute per admin session)

```javascript
// Add to routes/administration.ts:
router.get('/api/Users', security.isAuthorized(), ensureAdminRole, (req, res) => {
  // existing handler
})
```

**Verification:** Authenticate as a customer-role user, call `GET /api/Users` — confirm 403. Attempt to navigate to `/administration` with a customer JWT — confirm redirect to 403 page.

**Reference:** ➚ [CWE-285](https://cwe.mitre.org/data/definitions/285.html) Pillar ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · OWASP ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

#### <a id="m-005"></a>M-005 — Disable XXE and validate ZIP entry paths in file upload

**Addresses:**
- [F-006](#f-006) — XXE via libxml2 with noent:true
- [F-007](#f-007) — ZIP Slip path traversal in routes/fileUpload.ts
- [F-028](#f-028) — Unrestricted file type upload

**Prevents CWEs:**

- ➚ [CWE-611](https://cwe.mitre.org/data/definitions/611.html) — Improper Restriction of XML External Entity Reference (XXE)
- ➚ [CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Path Traversal
- ➚ [CWE-434](https://cwe.mitre.org/data/definitions/434.html) — Unrestricted Upload of File with Dangerous Type

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Medium

**Why:** XXE with `noent:true` enables blind SSRF and local file read in a single HTTP request from any unauthenticated user. ZIP Slip enables web shell deployment. Both are exploitable in under 60 seconds.

**How:**
1. In [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts), change `{ noent: true }` to `{ noent: false, nonet: true }` in the libxml2 parser options
2. For ZIP uploads, validate each entry path before extraction: `const safePath = path.resolve(destDir, entry.fileName); if (\!safePath.startsWith(destDir)) throw new Error('ZIP Slip detected')`
3. Add MIME type validation using `file-type` package — reject uploads whose magic bytes do not match the declared extension
4. Allowlist accepted file types: PDF, PNG, JPG, XML (with XXE disabled)

```javascript
// ZIP Slip prevention:
for (const entry of zipEntries) {
  const dest = path.resolve(uploadDir, entry.entryName)
  if (\!dest.startsWith(path.resolve(uploadDir))) {
    return res.status(400).json({ error: 'Invalid ZIP entry path' })
  }
}
```

**Verification:** Upload a ZIP with `../../evil.sh` entry — confirm the file is not created outside the upload directory. Upload a crafted XXE XML — confirm the server does not fetch the external entity.

**Reference:** ➚ [CWE-611](https://cwe.mitre.org/data/definitions/611.html) Pillar ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP ➚ [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/), ➚ [CWE-22](https://cwe.mitre.org/data/definitions/22.html) 🏆 Top 25 #5 · Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

#### <a id="m-006"></a>M-006 — Move JWT from localStorage to HttpOnly cookie

**Addresses:**
- [F-008](#f-008) — JWT stored in localStorage
- [F-040](#f-040) — Sensitive data in localStorage

**Prevents CWEs:** ➚ [CWE-922](https://cwe.mitre.org/data/definitions/922.html) — Insecure Storage of Sensitive Information

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Medium

**Why:** JWT in `localStorage` is readable by any JavaScript running on the page. A single XSS payload exfiltrates the token. HttpOnly cookies are invisible to JavaScript by specification.

**How:**
1. In `frontend/src/app/core/authentication.service.ts` _(file not found at review time)_, remove `localStorage.setItem('token', token)`
2. Change the server-side login response to `Set-Cookie: token=<jwt>; HttpOnly; Secure; SameSite=Strict; Path=/`
3. Update API calls to use `credentials: 'include'` — the browser will automatically attach the cookie
4. Remove `Authorization: Bearer` header construction from the Angular HTTP interceptor
5. Clear the cookie on logout: `Set-Cookie: token=; Max-Age=0; HttpOnly; Secure`

```typescript
// Before (authentication.service.ts):
localStorage.setItem('token', token)

// After — server sets HttpOnly cookie; client reads user info from a /api/whoami endpoint
this.currentUser$ = this.http.get<User>('/api/whoami')
```

**Verification:** Log in, open DevTools > Application > Local Storage — confirm no `token` key exists. Open DevTools > Application > Cookies — confirm `token` cookie has `HttpOnly` flag set.

**Reference:** ➚ [CWE-922](https://cwe.mitre.org/data/definitions/922.html) Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

#### <a id="m-007"></a>M-007 — Parameterize all raw SQL queries

**Addresses:**
- [F-009](#f-009) — SQL injection in product search
- [F-014](#f-014) — SQL injection in login

**Prevents CWEs:** ➚ [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Low

**Why:** SQL injection in both the login and search routes allows full database dump and authentication bypass. Parameterized queries are a one-line fix per affected route.

**How:**
1. In [routes/search.ts](vscode://file/home/mrohr/juice-shop/routes/search.ts), replace the raw template literal query with a Sequelize parameterized query: `models.sequelize.query('SELECT * FROM Products WHERE name LIKE ?', { replacements: ['%' + req.query.q + '%'] })`
2. In [routes/login.ts](vscode://file/home/mrohr/juice-shop/routes/login.ts), replace the raw email interpolation with a Sequelize `findOne({ where: { email: req.body.email } })`
3. Audit all other `sequelize.query()` calls for additional interpolation patterns

```javascript
// Before (routes/search.ts):
models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${req.query.q}%'`)

// After:
models.sequelize.query('SELECT * FROM Products WHERE name LIKE ?',
  { replacements: ['%' + req.query.q + '%'], type: models.sequelize.QueryTypes.SELECT })
```

**Verification:** Send `GET /rest/products/search?q='%20OR%20'1'%3D'1` — confirm the query returns only actual product matches, not all rows.

**Reference:** ➚ [CWE-89](https://cwe.mitre.org/data/definitions/89.html) 🏆 Top 25 #3 · Pillar ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/)

---

#### <a id="m-008"></a>M-008 — Replace notevil with static expression parser; add order audit log

**Addresses:**
- [F-010](#f-010) — RCE via notevil sandbox escape
- [F-029](#f-029) — CPU exhaustion DoS via complex expression
- [F-044](#f-044) — B2B orders not audited

**Prevents CWEs:**

- ➚ [CWE-94](https://cwe.mitre.org/data/definitions/94.html) — Improper Control of Generation of Code (Code Injection)
- ➚ [CWE-400](https://cwe.mitre.org/data/definitions/400.html) — Uncontrolled Resource Consumption
- ➚ [CWE-778](https://cwe.mitre.org/data/definitions/778.html) — Insufficient Logging

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** High

**Why:** `notevil` has known RCE sandbox escape vulnerabilities. The B2B endpoint passes user-supplied expressions directly to an evaluator — any expression evaluator is an attack surface. The only safe alternative for arithmetic expressions is a purpose-built parser that never touches `eval` or `Function`.

**How:**
1. Install `expr-eval` or `mathjs` (both use recursive descent parsers with no `eval`): `npm install expr-eval`
2. Replace `notevil` import and evaluation in [routes/b2bOrder.ts](vscode://file/home/mrohr/juice-shop/routes/b2bOrder.ts) with `Parser.evaluate(expression)`
3. Add expression complexity limit: reject expressions with nesting depth > 10 or length > 200 characters
4. Add structured audit log: `logger.info({ event: 'b2b_order', userId: req.user.id, expression, result })`
5. Remove `notevil` from `package.json` and run `npm audit` to confirm no residual vulnerabilities

```javascript
// Before:
const result = notevil.eval(req.body.orderLinesData)

// After:
import { Parser } from 'expr-eval'
const parser = new Parser()
if (req.body.orderLinesData.length > 200) return res.status(400).json({ error: 'Expression too long' })
const result = parser.evaluate(req.body.orderLinesData)
```

**Verification:** Send a known `notevil` sandbox escape payload — confirm the server returns 400 or evaluates it safely. Send `(9**9**9)` — confirm the server rejects it or returns the result without hanging.

**Reference:** ➚ [CWE-94](https://cwe.mitre.org/data/definitions/94.html) 🏆 Top 25 #11 · Pillar ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/)

---

#### <a id="m-009"></a>M-009 — Add field allowlist to User.create(); suppress stack traces

**Addresses:**
- [F-011](#f-011) — Mass assignment in user registration
- [F-047](#f-047) — Stack traces exposed in error responses

**Prevents CWEs:**

- ➚ [CWE-915](https://cwe.mitre.org/data/definitions/915.html) — Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)
- ➚ [CWE-209](https://cwe.mitre.org/data/definitions/209.html) — Generation of Error Message Containing Sensitive Information

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Low

**Why:** Mass assignment to `role: admin` at registration is a single HTTP request away from full privilege escalation. Suppressing stack traces in production eliminates information disclosure.

**How:**
1. In `routes/register.ts` _(file not found at review time)_, destructure only allowed fields before calling `User.create()`:
   `const { email, password, passwordRepeat, securityQuestion, securityAnswer } = req.body`
2. Pass only those fields to `User.create()` — never spread `req.body` directly
3. In the global error handler in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts), check `process.env.NODE_ENV === 'production'` and return only a generic error message without the stack trace

```javascript
// Before:
models.User.create(req.body)

// After:
const { email, password, passwordRepeat, securityQuestion, securityAnswer } = req.body
models.User.create({ email, password, passwordRepeat, securityQuestion, securityAnswer })
```

**Verification:** POST to `/api/Users` with `{ "email": "attacker@test.com", "password": "test", "role": "admin" }` — confirm the created user has `role: customer` in the database.

**Reference:** ➚ [CWE-915](https://cwe.mitre.org/data/definitions/915.html) Pillar ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP ➚ [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

---

### P2 — This Sprint

---

#### <a id="m-010"></a>M-010 — Restrict /ftp and log endpoints

**Addresses:**
- [F-012](#f-012) — Unauthenticated /ftp directory listing
- [F-032](#f-032) — Application logs served unauthenticated

**Prevents CWEs:**

- ➚ [CWE-548](https://cwe.mitre.org/data/definitions/548.html) — Exposure of Information Through Directory Listing
- ➚ [CWE-532](https://cwe.mitre.org/data/definitions/532.html) — Insertion of Sensitive Information into Log File

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** Unauthenticated FTP directory listing exposes acquisition documents and legal files. Unauthenticated log access leaks request parameters and user IDs. Both require a single middleware line to fix.

**How:**
1. Add `security.isAuthorized()` middleware to the `/ftp/` static file route in [server.ts](vscode://file/home/mrohr/juice-shop/server.ts)
2. Add the same middleware to the log access route
3. Consider disabling directory listing entirely: `express.static('ftp', { index: false })`

**Verification:** Attempt `GET /ftp/` without a JWT — confirm 401 is returned.

**Reference:** ➚ [CWE-548](https://cwe.mitre.org/data/definitions/548.html) Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

#### <a id="m-011"></a>M-011 — Replace security questions with email OTP for password reset

**Addresses:** [F-015](#f-015) — Password reset via guessable security answers

**Prevents CWEs:** ➚ [CWE-640](https://cwe.mitre.org/data/definitions/640.html) — Weak Password Recovery Mechanism

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Medium

**Why:** Security questions are trivially guessable or researchable from social media. Email OTP is a proven, low-friction alternative that doesn't require storing sensitive answers.

**How:**
1. Generate a cryptographically random 6-digit OTP: `crypto.randomInt(100000, 999999).toString()`
2. Store it with a 15-minute TTL (in-memory or Redis)
3. Send it via the existing email service
4. Verify the OTP before allowing password reset — invalidate after first use
5. Remove `securityQuestion` and `securityAnswer` from the user registration flow (or retain for legacy but don't use for reset)

**Verification:** Initiate password reset for a known account — confirm an OTP email is sent. Attempt reset with a guessed answer — confirm 400 is returned. Confirm OTP expires after 15 minutes.

**Reference:** ➚ [CWE-640](https://cwe.mitre.org/data/definitions/640.html) Pillar ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · OWASP ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

#### <a id="m-012"></a>M-012 — Enforce 2FA across all authentication paths

**Addresses:** [F-016](#f-016) — 2FA TOTP bypass

**Prevents CWEs:** ➚ [CWE-287](https://cwe.mitre.org/data/definitions/287.html) — Improper Authentication

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Medium

**Why:** 2FA that can be bypassed via OAuth login provides a false sense of security. Every authentication path must require the second factor for accounts that have 2FA enabled.

**How:**
1. After any successful first-factor authentication (including OAuth), check if the user has 2FA enabled
2. If enabled, issue a short-lived "pending 2FA" token (not the full session JWT) and redirect to the 2FA challenge
3. Only issue the full JWT after successful TOTP verification
4. Apply this gate in all auth paths: password login, OAuth callback, and API key endpoints

**Verification:** Enable 2FA on a test account. Authenticate via OAuth — confirm the TOTP challenge is presented before a session is granted.

**Reference:** ➚ [CWE-287](https://cwe.mitre.org/data/definitions/287.html) 🏆 Top 25 #14 · Pillar ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · OWASP ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

#### <a id="m-013"></a>M-013 — Add CSRF protection to state-changing endpoints

**Addresses:** [F-017](#f-017) — CSRF on password change

**Prevents CWEs:** ➚ [CWE-352](https://cwe.mitre.org/data/definitions/352.html) — Cross-Site Request Forgery (CSRF)

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** CSRF on password change allows silent account takeover from any page a victim visits. The fix is a single middleware registration.

**How:**
1. Install `csurf` or use the `SameSite=Strict` cookie attribute on the session token (simpler if migrating to HttpOnly cookies per [M-006](#m-006) — Move JWT from localStorage to HttpOnly cookie
2. If using cookies: set `SameSite=Strict` — this prevents the browser from including the cookie on cross-origin requests
3. If using header tokens: add `csurf` middleware to all state-changing routes (POST/PUT/PATCH/DELETE)

**Verification:** From a different origin, POST to `/rest/user/change-password` — confirm 403 is returned (or the cookie is not included, yielding 401).

**Reference:** ➚ [CWE-352](https://cwe.mitre.org/data/definitions/352.html) 🏆 Top 25 #9 · Pillar ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · OWASP ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

#### <a id="m-014"></a>M-014 — Add ownership check to basket and order routes

**Addresses:** [F-018](#f-018) — IDOR on basket and order endpoints

**Prevents CWEs:** ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) — Improper Access Control

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** Any authenticated user can read or modify any other user's basket or orders by iterating numeric IDs. This is a simple ownership comparison.

**How:**
1. In [routes/basket.ts](vscode://file/home/mrohr/juice-shop/routes/basket.ts), after loading the basket by ID, verify `basket.UserId === req.user.id`
2. Apply the same pattern to order routes
3. Return 403 (not 404) to avoid leaking whether the resource exists

```javascript
// Add after loading the basket:
if (basket.UserId \!== req.user.id && req.user.role \!== 'admin') {
  return res.status(403).json({ error: 'Access denied' })
}
```

**Verification:** Authenticate as user A, attempt `GET /api/BasketItems` with user B's basket ID — confirm 403 is returned.

**Reference:** ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) OWASP ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

#### <a id="m-015"></a>M-015 — Fix NoSQL injection and add author binding in reviews

**Addresses:**
- [F-019](#f-019) — NoSQL injection via $where in reviews
- [F-020](#f-020) — Mass update IDOR in reviews
- [F-041](#f-041) — Reviews not bound to verified identity

**Prevents CWEs:**

- ➚ [CWE-943](https://cwe.mitre.org/data/definitions/943.html) — Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)
- ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) — Improper Access Control
- ➚ [CWE-345](https://cwe.mitre.org/data/definitions/345.html) — Insufficient Verification of Data Authenticity

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** `$where` NoSQL injection enables server-side JavaScript execution in the MarsDB collection engine (an in-process MongoDB-compatible store; no Mongoose driver is used). Mass update IDOR allows any user to overwrite all product reviews. Review identity binding prevents attribution forgery.

**How:**
1. In [routes/showProductReviews.ts](vscode://file/home/mrohr/juice-shop/routes/showProductReviews.ts), replace `{ $where: ... }` with a scalar-only predicate such as `db.reviewsCollection.find({ product: Number(req.params.id) })` — validate `req.params.id` is a positive integer before the call and reject the request otherwise.
2. In [routes/updateProductReviews.ts](vscode://file/home/mrohr/juice-shop/routes/updateProductReviews.ts), change `db.reviewsCollection.update({ _id: req.body.id }, …, { multi: true })` to `db.reviewsCollection.update({ _id: req.body.id, author: req.user.email }, …, { multi: false })` — the additional author clause is the authorization check, and `multi: false` prevents fan-out.
3. In [routes/createProductReviews.ts](vscode://file/home/mrohr/juice-shop/routes/createProductReviews.ts), set `author: req.user.email` from the JWT claims rather than from `req.body.author` so the review cannot be forged.

**Verification:** Send a review query with `{ "$where": "sleep(2000)" }` — confirm the server does not delay. Attempt to update another user's review — confirm 403 is returned.

**Reference:** ➚ [CWE-943](https://cwe.mitre.org/data/definitions/943.html) Pillar ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/)

---

#### <a id="m-016"></a>M-016 — Migrate OAuth to PKCE authorization code flow

**Addresses:**
- [F-021](#f-021) — OAuth implicit flow used in frontend
- [F-045](#f-045) — OAuth implicit flow token in URL fragment

**Prevents CWEs:**

- ➚ [CWE-522](https://cwe.mitre.org/data/definitions/522.html) — Insufficiently Protected Credentials
- ➚ [CWE-598](https://cwe.mitre.org/data/definitions/598.html) — Use of GET Request Method With Sensitive Query Strings

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Medium

**Why:** OAuth implicit flow delivers access tokens in URL fragments, exposing them to browser history and referrer headers. PKCE authorization code flow delivers tokens via a server-side POST, completely invisible to the browser URL bar.

**How:**
1. Register a new OAuth client configuration with `response_type=code` instead of `response_type=token`
2. Implement PKCE: generate `code_verifier` and `code_challenge` in [frontend/src/app/oauth/oauth.component.ts](vscode://file/home/mrohr/juice-shop/frontend/src/app/oauth/oauth.component.ts)
3. Exchange the authorization code for tokens server-side (backend-to-backend), never in the browser
4. The browser receives only a session cookie (HttpOnly) — no access token in JavaScript

**Verification:** Complete an OAuth login flow — confirm the callback URL contains a `code` parameter, not an `access_token` fragment. Confirm no token appears in browser history.

**Reference:** ➚ [CWE-522](https://cwe.mitre.org/data/definitions/522.html) Pillar ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · OWASP ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

#### <a id="m-017"></a>M-017 — Remove DomSanitizer bypasses and innerHTML assignments

**Addresses:**
- [F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()
- [F-025](#f-025) — DOM XSS via innerHTML assignments in Angular

**Prevents CWEs:** ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation (XSS)

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Medium

**Why:** `bypassSecurityTrustHtml` disables Angular's built-in XSS protection entirely for the affected binding. Stored XSS in product descriptions can steal tokens from all users who view the page.

**How:**
1. Search for all `bypassSecurityTrustHtml` calls in `frontend/src/`: `grep -r 'bypassSecurityTrustHtml' frontend/src/`
2. For each occurrence, determine if HTML rendering is actually required. If not, use `textContent` or plain Angular template binding `{{ variable }}`
3. If rich text display is required (e.g., product descriptions), use a whitelist-based HTML sanitizer like `DOMPurify` before passing to `bypassSecurityTrustHtml`
4. Replace all `element.innerHTML = userInput` patterns with `element.textContent = userInput`

**Verification:** Create a product with name `<img src=x onerror=alert(1)>` — confirm the image tag is rendered as text, not executed.

**Reference:** ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html) 🏆 Top 25 #2 · Pillar ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/)

---

#### <a id="m-018"></a>M-018 — Disable YAML entity expansion in file upload

**Addresses:** [F-026](#f-026) — YAML bomb (billion laughs) in file upload

**Prevents CWEs:** ➚ [CWE-400](https://cwe.mitre.org/data/definitions/400.html) — Uncontrolled Resource Consumption

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** Recursive YAML anchors expand exponentially in memory. A 1KB input can consume gigabytes of RAM, crashing the server.

**How:**
1. In [routes/fileUpload.ts](vscode://file/home/mrohr/juice-shop/routes/fileUpload.ts), use `js-yaml` with `{ schema: FAILSAFE_SCHEMA }` or switch to `safeLoad` (deprecated) / `load` with no schema that supports anchors
2. Add a cap: reject any YAML file exceeding 10,000 nodes after parsing
3. Alternatively, reject YAML uploads entirely if they are not required for a documented use case

**Verification:** Upload a billion-laughs YAML payload — confirm the server rejects it with 400 or 413 rather than hanging or crashing.

**Reference:** ➚ [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/)

---

#### <a id="m-019"></a>M-019 — Add URL allowlist for profile image fetch (SSRF prevention)

**Addresses:** [F-027](#f-027) — SSRF via profile image URL

**Prevents CWEs:** ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html) — Server-Side Request Forgery (SSRF)

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** SSRF from a public endpoint enables probing of internal services, cloud metadata APIs, and potentially triggers further exploits on internal systems.

**How:**
1. In [routes/profileImageUrlUpload.ts](vscode://file/home/mrohr/juice-shop/routes/profileImageUrlUpload.ts), parse the URL and verify the hostname against an allowlist of known image CDNs
2. Block all private IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (link-local / metadata)
3. Perform a DNS lookup after allowlist check to prevent DNS rebinding: resolve the hostname and verify the resolved IP is not in a private range
4. Set a short fetch timeout (3 seconds) to prevent slow-read attacks

```javascript
const url = new URL(req.body.imageUrl)
const allowed = ['imgur.com', 'gravatar.com', 'example-cdn.com']
if (\!allowed.includes(url.hostname)) return res.status(400).json({ error: 'Image host not allowed' })
```

**Verification:** POST a profile image URL of `http://169.254.169.254/latest/meta-data/` — confirm 400 is returned.

**Reference:** ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html) 🏆 Top 25 #19 · Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A10:2021](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

---

#### <a id="m-020"></a>M-020 — Add admin role check and audit logging to chatbot

**Addresses:**
- [F-030](#f-030) — Chatbot admin functions without role check
- [F-042](#f-042) — User data leakage via username injection
- [F-043](#f-043) — Chatbot interactions not logged

**Prevents CWEs:**

- ➚ [CWE-285](https://cwe.mitre.org/data/definitions/285.html) — Improper Authorization
- ➚ [CWE-200](https://cwe.mitre.org/data/definitions/200.html) — Exposure of Sensitive Information to an Unauthorized Actor
- ➚ [CWE-778](https://cwe.mitre.org/data/definitions/778.html) — Insufficient Logging

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** Admin-level operations through the chatbot are accessible to any authenticated user. Chatbot interactions with admin consequences must be role-gated and logged for auditability.

**How:**
1. In [routes/chatbot.ts](vscode://file/home/mrohr/juice-shop/routes/chatbot.ts), check `req.user.role === 'admin'` before executing any admin action (coupon generation, user lookup)
2. Return a generic "I can't help with that" response for non-admin users rather than revealing the capability exists
3. Sanitize the username from the JWT before embedding it in chatbot responses: strip template syntax and special characters
4. Add structured logging for all chatbot interactions: `logger.info({ event: 'chatbot_action', userId, action, result })`

**Verification:** Authenticate as a customer, send an admin command to the chatbot — confirm the admin action is not executed and no admin-level data is returned.

**Reference:** ➚ [CWE-285](https://cwe.mitre.org/data/definitions/285.html) Pillar ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · OWASP ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

#### <a id="m-021"></a>M-021 — Restrict CORS to allowed origins

**Addresses:** [F-031](#f-031) — CORS wildcard Access-Control-Allow-Origin: *

**Prevents CWEs:** ➚ [CWE-942](https://cwe.mitre.org/data/definitions/942.html) — Permissive Cross-domain Policy with Untrusted Domains

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** Wildcard CORS enables cross-origin reads of authenticated API responses in scenarios where the session token is in a cookie. It also allows attacker-controlled pages to interact with the API using the victim's session.

**How:**
1. In [server.ts](vscode://file/home/mrohr/juice-shop/server.ts), replace `{ origin: '*' }` with `{ origin: ['https://yourdomain.com'], credentials: true }`
2. If multiple environments are needed, maintain an allowlist: `const allowed = process.env.CORS_ORIGINS?.split(',') ?? []`
3. Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`

**Verification:** From `https://evil.com`, attempt a cross-origin fetch to the API — confirm the response is blocked by the browser CORS policy.

**Reference:** ➚ [CWE-942](https://cwe.mitre.org/data/definitions/942.html) Pillar ➚ [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP ➚ [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

#### <a id="m-022"></a>M-022 — Restrict /metrics endpoint to internal networks

**Addresses:** [F-034](#f-034) — Prometheus /metrics unauthenticated

**Prevents CWEs:** ➚ [CWE-200](https://cwe.mitre.org/data/definitions/200.html) — Exposure of Sensitive Information to an Unauthorized Actor

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Low

**Why:** Prometheus metrics reveal internal architecture, route popularity, error rates, and heap statistics — all useful for planning targeted attacks.

**How:**
1. In [server.ts](vscode://file/home/mrohr/juice-shop/server.ts), add IP-based middleware before the metrics route:
   `app.use('/metrics', (req, res, next) => { if (\!isInternalIP(req.ip)) return res.status(403).end(); next() })`
2. Alternatively, move metrics to a separate port (e.g., 9091) bound only to `127.0.0.1`
3. If Prometheus scrape requires network access, protect with a bearer token header

**Verification:** Request `GET /metrics` from an external IP address — confirm 403 is returned.

**Reference:** ➚ [CWE-200](https://cwe.mitre.org/data/definitions/200.html) Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/)

---

#### <a id="m-027"></a>M-027 — Authenticate `Socket.IO` WS upgrade and validate Origin

**Addresses:** [F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade

**Prevents CWEs:** ➚ [CWE-306](https://cwe.mitre.org/data/definitions/306.html) — Missing Authentication for Critical Function

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Medium

**Why:** The `Socket.IO` WS upgrade currently accepts any client on the same host/port as the REST API, with no JWT check on `connection` and no origin validation. Challenge-verification events carry client-supplied payloads that poison challenge state and cannot be repudiated because there is no logged identity on the connection.

**How:**
1. In [server.ts](vscode://file/home/mrohr/juice-shop/server.ts) where `Socket.IO` is attached, add an `io.use()` middleware that reads `socket.handshake.auth.token` (or the `Authorization` header sent during the upgrade handshake) and calls the same JWT verify used by REST routes. Reject with `next(new Error('unauthenticated'))` when missing or invalid.
2. Validate `socket.handshake.headers.origin` against a static allowlist (the deployed web origin) — reject otherwise.
3. For each event handler, enforce per-event authorization before emitting state changes: e.g. the challenge-verification events should run a server-side check against `routes/dataErasure` style session state, not trust the payload.
4. Add connect-storm rate limiting via `express-rate-limit` applied at the HTTP-upgrade level or via a bucket keyed on `socket.handshake.address`.
5. Log every WS `connection` and disconnect with authenticated user ID to the structured auth log (see [M-023](#m-023) — Add token revocation list and structured auth logging

**Verification:** Open a WebSocket to `wss://<host>/socket.io/?EIO=4&transport=websocket` with no auth — confirm the server closes the connection with a handshake-level error. Repeat with a forged origin header — confirm rejection.

**Reference:** ➚ [CWE-306](https://cwe.mitre.org/data/definitions/306.html) 🏆 Top 25 #13 · Pillar ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · OWASP ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

#### <a id="m-028"></a>M-028 — Pin container base images and lock down training data

**Addresses:**
- [F-050](#f-050) — Supply-chain / container hygiene
- [F-051](#f-051) — Chatbot trainingData URL fetched without validation

**Prevents CWEs:**

- ➚ [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) — Use of Unmaintained Third Party Components
- ➚ [CWE-506](https://cwe.mitre.org/data/definitions/506.html) — Embedded Malicious Code
- ➚ [CWE-829](https://cwe.mitre.org/data/definitions/829.html) — Inclusion of Functionality from Untrusted Control Sphere
- ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html) — Server-Side Request Forgery (SSRF)

**Priority:** **P2 — This Sprint**

**Severity:** 🟠 High

**Effort:** Medium

**Why:** A floating `FROM node:24` tag allows a silent substitution of the base image. `npm install --unsafe-perm` combined with postinstall scripts enables transitive publishers to execute arbitrary code at build time. The chatbot `trainingData` URL is an unvalidated URL that, if mutated upstream, substitutes the model's intent-matching rules — a concrete OWASP LLM03 training-data poisoning vector.

**How:**
1. In [Dockerfile](vscode://file/home/mrohr/juice-shop/Dockerfile), replace `FROM node:24` with `FROM node:24@sha256:<digest>` (pin to a specific digest) and document the rotation procedure.
2. Replace `npm install --omit=dev --unsafe-perm` with `npm ci --omit=dev --ignore-scripts` and run any required postinstalls explicitly for audited packages only.
3. In [package.json](vscode://file/home/mrohr/juice-shop/package.json), replace the recursive `postinstall` that runs `cd frontend && npm install` with an explicit build-stage command in the Dockerfile, using `npm ci --ignore-scripts` for the frontend workspace.
4. In `.github/workflows/*.yml`, pin `actions/checkout` and every third-party action to a full-length commit SHA, not a branch or short tag; enable Dependabot's "github-actions" ecosystem.
5. In [routes/chatbot.ts](vscode://file/home/mrohr/juice-shop/routes/chatbot.ts) (or the bootstrap code that loads `juicy-chat-bot`), read `trainingData` URL from config and validate it against an allowlist (e.g. `^https://cdn\.juice-shop\.com/bot/training/[a-z0-9-]+\.json$`). Compute SHA-256 of the fetched training set and compare against a committed `trainingData.sha256` before loading.
6. Reject `http://`, `file://`, `data:`, and RFC-1918 destinations outright.

**Verification:** Rebuild the image and confirm the pinned digest appears in `docker inspect`. Run `npm ls --omit=dev` and confirm no postinstall scripts executed. Flip `trainingData` in `config/default.yml` to `http://169.254.169.254/` and confirm the bot bootstrap refuses to start.

**Reference:** ➚ [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) Pillar ➚ [CWE-710](https://cwe.mitre.org/data/definitions/710.html) · OWASP ➚ [A06:2021](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/), ➚ [CWE-829](https://cwe.mitre.org/data/definitions/829.html) Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/), ➚ [CWE-506](https://cwe.mitre.org/data/definitions/506.html) Pillar ➚ [CWE-710](https://cwe.mitre.org/data/definitions/710.html) · OWASP ➚ [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/), ➚ [OWASP LLM03](https://genai.owasp.org/llmrisk/llm03/)

---

### P3 — Next Quarter

---

#### <a id="m-023"></a>M-023 — Add token revocation list and structured auth logging

**Addresses:**
- [F-035](#f-035) — Auth token revocation absent
- [F-048](#f-048) — Authentication events not logged

**Prevents CWEs:**

- ➚ [CWE-613](https://cwe.mitre.org/data/definitions/613.html) — Insufficient Session Expiration
- ➚ [CWE-778](https://cwe.mitre.org/data/definitions/778.html) — Insufficient Logging

**Priority:** **P3 — Next Quarter**

**Severity:** 🟡 Medium

**Effort:** Medium

**Why:** Stateless JWTs cannot be revoked — a stolen token is valid until expiry regardless of logout. Structured auth logging is required for incident detection and forensic response.

**How:**
1. Maintain a Redis set of revoked JTIs (JWT IDs): on logout, add the JTI with TTL equal to the token's remaining lifetime
2. In the JWT verification middleware, check whether the JTI is in the revocation set
3. Add a `jti` field (UUID) to all issued JWTs
4. Add structured log entries for: login success, login failure, logout, password change, 2FA enrollment/unenrollment — include `userId`, `ip`, `userAgent`, `timestamp`

**Verification:** Log in, capture the JWT, log out, then use the captured JWT on an authenticated endpoint — confirm 401 is returned. Confirm login events appear in the structured log.

**Reference:** ➚ [CWE-613](https://cwe.mitre.org/data/definitions/613.html) Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

#### <a id="m-024"></a>M-024 — Add rate limiting and progressive lockout to auth endpoints

**Addresses:**
- [F-036](#f-036) — No rate limiting on auth endpoints
- [F-038](#f-038) — No account lockout on failed logins

**Prevents CWEs:** ➚ [CWE-307](https://cwe.mitre.org/data/definitions/307.html) — Improper Restriction of Excessive Authentication Attempts

**Priority:** **P3 — Next Quarter**

**Severity:** 🟡 Medium

**Effort:** Low

**Why:** Unlimited login attempts enable credential stuffing at network speed. Rate limiting to 10 attempts per minute per IP is sufficient to stop automated attacks.

**How:**
1. Install `express-rate-limit`: `npm install express-rate-limit`
2. Apply to `/rest/user/login`, `/api/Users` (POST), and `/rest/user/reset-password`:
   ```javascript
   const loginLimiter = rateLimit({ windowMs: 60000, max: 10, message: 'Too many attempts' })
   app.use('/rest/user/login', loginLimiter)
   ```
3. Add progressive delay on repeated failures: 1s, 2s, 4s, 8s (exponential backoff)
4. After 10 consecutive failures, temporarily lock the account for 15 minutes

**Verification:** Send 20 rapid login requests — confirm requests 11+ receive 429 responses.

**Reference:** ➚ [CWE-307](https://cwe.mitre.org/data/definitions/307.html) Pillar ➚ [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · OWASP ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

#### <a id="m-025"></a>M-025 — Allowlist redirect destinations

**Addresses:** [F-037](#f-037) — Open redirect via to parameter

**Prevents CWEs:** ➚ [CWE-601](https://cwe.mitre.org/data/definitions/601.html) — URL Redirection to Untrusted Site (Open Redirect)

**Priority:** **P3 — Next Quarter**

**Severity:** 🟡 Medium

**Effort:** Low

**Why:** Open redirects are routinely used in phishing campaigns to make malicious URLs appear to originate from a trusted domain.

**How:**
1. In [routes/redirect.ts](vscode://file/home/mrohr/juice-shop/routes/redirect.ts), replace the current weak prefix check with an explicit allowlist of permitted destinations
2. Alternatively, use relative-path-only redirects (strip the scheme and host entirely)
3. Return 400 for any redirect target not in the allowlist

**Verification:** Request `/redirect?to=https://evil.com` — confirm 400 is returned.

**Reference:** ➚ [CWE-601](https://cwe.mitre.org/data/definitions/601.html) Pillar ➚ [CWE-664](https://cwe.mitre.org/data/definitions/664.html) · OWASP ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

### P4 — Backlog

---

#### <a id="m-026"></a>M-026 — Implement Content Security Policy

**Addresses:** [F-039](#f-039) — Missing Content Security Policy

**Prevents CWEs:** ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) — Protection Mechanism Failure

**Priority:** **P4 — Backlog**

**Severity:** 🟡 Medium

**Effort:** High

**Why:** CSP is a critical defense-in-depth control that limits the blast radius of XSS vulnerabilities. It prevents inline script execution and restricts script sources, making successful XSS far less impactful. The effort is High because Juice Shop uses inline styles and scripts extensively — a CSP rollout requires auditing and refactoring all inline content.

**How:**
1. Start with a report-only policy: `Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; report-uri /csp-report`
2. Monitor violation reports to identify inline scripts and external sources
3. Migrate inline scripts to external files; replace `eval()` calls with safe alternatives
4. Graduate to enforcement mode once violation rate drops to zero
5. Target policy: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'`

**Verification:** Set the enforcement CSP header. Load the application — confirm no CSP violations appear in the browser console for normal user flows.

**Reference:** ➚ [CWE-693](https://cwe.mitre.org/data/definitions/693.html) OWASP ➚ [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

## 10. Out of Scope

The following areas were not analyzed in this assessment:

- **Infrastructure hardening** — OS-level configuration, network firewall rules, cloud IAM roles, Kubernetes RBAC, and container security profiles are outside the application-layer scope of this review.
- **Third-party services** — external OAuth providers (Google, GitHub), CDN configuration, and DNS security (DNSSEC) were not evaluated.
- **Physical security** — data center access controls, hardware security modules, and physical key management are not in scope.
- **Penetration testing** — this threat model identifies design-level and code-level threats. It is not a substitute for active penetration testing, which may discover runtime misconfigurations not visible in static analysis.
- **Compliance certification** — this assessment identifies control gaps relevant to PCI-DSS, OWASP ASVS, and GDPR but does not constitute a formal compliance audit or certification.
- **Client device security** — browser security settings, client-side certificate management, and end-user device hardening are outside scope.
- **Social engineering** — phishing attacks targeting administrators and developers are not modeled here.
- **Challenge solutions** — Juice Shop is intentionally vulnerable. Vulnerabilities marked as "intentional challenges" (e.g., visible score board, challenge flags) were noted but not modeled as threats since they are deliberate design choices for the training application.


## Appendix: Run Statistics

| Field | Value |
|------- |------- |
| **Total Duration** | 44 min 48 s |
| **Mode** | full |
| **Assessment Depth** | thorough |
| **Plugin Version** | 0.9.0-beta |
| **Analysis Version** | 1 |
| **Orchestrator Model** | claude-sonnet-4-6 |
| **Agent Models** | context-resolver: claude-sonnet-4-6 · recon-scanner: claude-sonnet-4-6 · stride-analyzer: claude-sonnet-4-6 · triage-validator: claude-opus-4-7 |
| **Repository** | /home/mrohr/juice-shop |
| **Output Directory** | /home/mrohr/juice-shop/docs/security |

### Per-Phase Duration Breakdown

| Phase | Description | Duration |
|------- |------------- |---------- |
| 1 | Context Resolution | ~30s |
| 2 | Reconnaissance | ~6m |
| 3 | Architecture Modeling | ~2m |
| 4 | Security Use Cases | ~2m |
| 5 | Asset Identification | ~1m |
| 6 | Attack Surface Mapping | ~1m |
| 7 | Trust Boundary Analysis | ~1m 30s |
| 8 | Security Controls Catalog | ~3m |
| 9 | STRIDE Threat Enumeration (8 components) | ~25m |
| 10 | Scan Synthesis | ~30s |
| 10b | Triage Validation | ~1m |
| 11 | Finalization | ~1m |
| **Total** | | **~44m 48s** |

### Coverage Summary

| Metric | Value |
|-------- |------- |
| Components Analyzed | 8 |
| Threats Identified | 47 ([F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts[F-047](#f-047) — Stack traces exposed in error responses |
| Critical Threats | 10 |
| High Threats | 23 |
| Medium Threats | 14 |
| Low Threats | 0 |
| Mitigations Generated | 26 ([M-001](#m-001) — Rotate all hardcoded secrets[M-026](#m-026) — Implement Content Security Policy |
| P1 Mitigations | 9 |
| P2 Mitigations | 13 |
| P3 Mitigations | 3 |
| P4 Mitigations | 1 |
| Security Controls Rated | 21 |
| Controls Adequate | 1 |
| Controls Partial | 3 |
| Controls Weak | 4 |
| Controls Missing | 13 |

### Agent Dispatch Log

| Agent | Model | Purpose |
|------- |------- |--------- |
| appsec-context-resolver | claude-sonnet-4-6 | External context + requirements |
| appsec-recon-scanner | claude-sonnet-4-6 | Codebase reconnaissance |
| appsec-stride-analyzer × 8 | claude-sonnet-4-6 | STRIDE threat enumeration per component |

---

## <a id="appendix-a-vektor-taxonomy"></a>Appendix A — Vektor Taxonomy

Canonical source: [plugin/data/breach-vector-taxonomy.yaml](../../../appsec-advisor/plugin/data/breach-vector-taxonomy.yaml). Each entry defines one attacker position / exposure class used in the Vektor column across this document. The taxonomy is deliberately coarse (7 categories) so reviewers can group findings by reachability at a glance.

| Vektor | Breach Distance | Attacker Position | Examples |
|--- |--- |--- |--- |
| [internet-anon](#vektor-internet-anon) | 1 | Unauthenticated attacker from the public internet | [F-009](#f-009) — SQL injection in product search<br/>[F-014](#f-014) — SQL injection in login<br/>[F-049](#f-049) — Unauthenticated `Socket.IO` WebSocket upgrade |
| [internet-user](#vektor-internet-user) | 2 | Any authenticated low-privilege user | [F-010](#f-010) — RCE via notevil sandbox escape<br/>[F-027](#f-027) — SSRF via profile image URL<br/>[F-028](#f-028) — Unrestricted file type upload |
| [internet-priv-user](#vektor-internet-priv-user) | 2 | Authenticated admin-level user | [F-023](#f-023) — Admin panel client-side guard only<br/>[F-046](#f-046) — Admin user deletion without safeguards |
| [victim-required](#vektor-victim-required) | 2 | Needs victim interaction (XSS, CSRF, open redirect) | [F-017](#f-017) — CSRF on password change<br/>[F-024](#f-024) — XSS via DomSanitizer.bypassSecurityTrustHtml()<br/>[F-025](#f-025) — DOM XSS via innerHTML assignments in Angular |
| [build-time](#vektor-build-time) | 3 | Attacker controls a build input (dep, base image, CI, training data) | [F-051](#f-051) — Chatbot trainingData URL fetched without validation<br/>[F-052](#f-052) — Dockerfile base image uses floating tag<br/>[F-054](#f-054) — package.json postinstall hook<br/>[AF-007](#af-007) — No supply-chain integrity controls |
| [repo-read](#vektor-repo-read) | 3 | Attacker gains read access to source repository | [F-001](#f-001) — Hardcoded RSA private key in lib/insecurity.ts<br/>[F-002](#f-002) — Password hashing uses MD5 without salt<br/>[AF-002](#af-002) — All secrets embedded in source code |
| [n-a](#vektor-n-a) | — | Architectural / meta-finding with no runtime entry point | [AF-001](#af-001) — Monolith with no separation<br/>[AF-002](#af-002) — All secrets embedded in source code<br/>[AF-003](#af-003) — Unsafe code execution pattern |

### <a id="vektor-internet-anon"></a>Internet Anon

**Breach distance:** 1 — Internet-reachable.
**Attacker position:** Unauthenticated attacker from the public internet.
**Preconditions:** Endpoint is reachable from the internet (no IP allowlist, no VPN) AND no authentication middleware blocks the request.
**Typical CWEs:** ➚ [CWE-89](https://cwe.mitre.org/data/definitions/89.html), ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ➚ [CWE-306](https://cwe.mitre.org/data/definitions/306.html), ➚ [CWE-327](https://cwe.mitre.org/data/definitions/327.html), ➚ [CWE-611](https://cwe.mitre.org/data/definitions/611.html), ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/), ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/).

### <a id="vektor-internet-user"></a>Internet User

**Breach distance:** 2 — Authenticated low-privilege user.
**Attacker position:** Any authenticated low-privilege user (valid JWT / session).
**Preconditions:** Attacker has signed up or otherwise obtained a valid user session AND endpoint is behind auth but not behind role/admin checks.
**Typical CWEs:** ➚ [CWE-287](https://cwe.mitre.org/data/definitions/287.html), ➚ [CWE-352](https://cwe.mitre.org/data/definitions/352.html), ➚ [CWE-434](https://cwe.mitre.org/data/definitions/434.html), ➚ [CWE-611](https://cwe.mitre.org/data/definitions/611.html), ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), ➚ [A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/), ➚ [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/), ➚ [A10:2021](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/).

### <a id="vektor-internet-priv-user"></a>Internet Priv User

**Breach distance:** 2 — Authenticated admin-level user.
**Attacker position:** Authenticated admin-level user (JWT with admin role or equivalent).
**Preconditions:** Attacker holds admin credentials or has elevated privileges AND endpoint is gated on admin role but still exploitable once reached.
**Typical CWEs:** ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ➚ [CWE-94](https://cwe.mitre.org/data/definitions/94.html), ➚ [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/).

### <a id="vektor-victim-required"></a>Victim-Required

**Breach distance:** 2 — Requires user interaction.
**Attacker position:** Attacker needs victim interaction — social engineering, crafted link, or live session.
**Preconditions:** Victim must click a link, load a page, or have an active session. Applies to XSS, CSRF, click-jacking, open redirect.
**Typical CWEs:** ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ➚ [CWE-352](https://cwe.mitre.org/data/definitions/352.html), ➚ [CWE-601](https://cwe.mitre.org/data/definitions/601.html), ➚ [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/).

### <a id="vektor-build-time"></a>Build-Time

**Breach distance:** 3 — Supply-chain position.
**Attacker position:** Attacker controls a build input — CI runner, dependency, base image, or external data fetched during build.
**Preconditions:** Compromise of a dependency, registry, or base image OR compromise of a CI runner with write access to artifacts.
**Typical CWEs:** ➚ [CWE-506](https://cwe.mitre.org/data/definitions/506.html), ➚ [CWE-829](https://cwe.mitre.org/data/definitions/829.html), ➚ [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html), ➚ [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html).
**Typical OWASP Top 10:** ➚ [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/).
**OWASP LLM:** ➚ [LLM03:2025](https://genai.owasp.org/llmrisk/llm03-2025-supply-chain/), ➚ [LLM04:2025](https://genai.owasp.org/llmrisk/llm04-2025-data-and-model-poisoning/).

### <a id="vektor-repo-read"></a>Repo-Read

**Breach distance:** 3 — Source-code access required.
**Attacker position:** Attacker gains read access to source repository (leaked clone, forked fork, insider, compromised developer workstation).
**Preconditions:** Read access to the source tree at or after commit time — no runtime exploit needed; the vulnerability is the content of the repo.
**Typical CWEs:** ➚ [CWE-312](https://cwe.mitre.org/data/definitions/312.html), ➚ [CWE-540](https://cwe.mitre.org/data/definitions/540.html), ➚ [CWE-798](https://cwe.mitre.org/data/definitions/798.html).
**Typical OWASP Top 10:** ➚ [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/), ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/).

### <a id="vektor-n-a"></a>n/a

**Breach distance:** not applicable.
**Attacker position:** Architectural / meta-finding — no runtime entry point. The finding describes a design defect that aggregates multiple code-level findings.
**Preconditions:** Finding ID starts with `AF-` (architectural) rather than `F-` (code-level).
**Typical CWEs:** none (AFs do not carry a primary CWE directly).
**Typical OWASP Top 10:** derived from the aggregated children (see each AF's own references).
| appsec-triage-validator | claude-opus-4-7 | Cross-component triage validation |