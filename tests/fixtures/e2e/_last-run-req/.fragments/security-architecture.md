## 7. Security Architecture

This chapter is organized by security-control category. The architecture section avoids artificial control IDs and finding-ID columns in overview tables. Findings are listed only where the affected control is described.

_§7 schema v2 (13-section control-category layout). Cataloged controls: 16 total — 0 adequate, 1 partial, 1 weak, 1 unsafe, 13 missing. Linked threats: 13._

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
| [7.2 Identity and Authentication Controls](#72-identity-and-authentication-controls) | 🔴 Missing | Required controls not in place (e.g. Password-Based Authentication). |
| [7.3 Session and Token Controls](#73-session-and-token-controls) | 🔴 Missing | Required controls not in place (e.g. Session Management). |
| [7.4 Authorization Controls](#74-authorization-controls) | 🔴 Missing | 2 routed findings; required controls not in place (e.g. Role-Based Access Control). |
| [7.5 Query Construction and Data Access Controls](#75-query-construction-and-data-access-controls) | 🟡 Partial | 0 routed findings; 1 partial control (e.g. Parameterized Queries / ORM) leave gaps. |
| [7.6 Input Boundary Validation Controls](#76-input-boundary-validation-controls) | 🔴 Missing | 2 routed findings; required controls not in place (e.g. Input Validation). |
| [7.7 Output Encoding and Rendering Controls](#77-output-encoding-and-rendering-controls) | 🔴 Missing | Required controls not in place (e.g. Output Encoding). |
| [7.8 Browser and Cross-Origin Controls](#78-browser-and-cross-origin-controls) | 🔴 Missing | 1 routed finding; required controls not in place (e.g. Security Headers (helmet), CORS Configuration). |
| [7.9 Cryptography Secrets and Data Protection](#79-cryptography-secrets-and-data-protection) | 🔴 Missing | Required controls not in place (e.g. Password Hashing, Transport Layer Security). |
| [7.10 File Parser and Outbound Request Controls](#710-file-parser-and-outbound-request-controls) | 🔴 Missing | 1 routed finding; required controls not in place (e.g. Rate Limiting). |
| [7.11 Operations Runtime and Supply Chain Controls](#711-operations-runtime-and-supply-chain-controls) | 🔴 Unsafe | 2 routed findings; catalogued controls are present but defeated (e.g. Container Security Hardening, Dependency Pinning and SCA). |
| [7.12 Real-time and Not Applicable Controls](#712-real-time-and-not-applicable-controls) | — | No controls or findings routed to this category. |
| [7.13 Defense-in-Depth Summary](#713-defense-in-depth-summary) | — | No controls or findings routed to this category. |

<!-- §7.1 MECHANICAL-FROZEN END -->

### 7.2 Identity and Authentication Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.2 Identity and Authentication Controls — Registration, password login, OAuth/OIDC adapters, MFA/TOTP, JWT issuance and verification, password reset/change. -->

<!-- §7.2 AUTH-MECHANISMS-FROZEN — deterministic inventory, pregenerator-owned. DO NOT EDIT. -->
**Authentication mechanisms (at a glance).** Every authentication mechanism detected on the application, its effective status, where it is assessed, and its linked findings. Controls are catalogued by domain, so JWT/session handling is assessed under [§7.3 Session and Token Controls](#73-session-and-token-controls) and password hashing under [§7.9 Cryptography Secrets and Data Protection](#79-cryptography-secrets-and-data-protection).

| Mechanism | Status | Assessed in | Findings |
|---|---|---|---|
| Password login | 🔴 Missing | [§7.2](#72-identity-and-authentication-controls) | — |
| Password storage (hashing) | 🔴 Missing | [§7.9](#79-cryptography-secrets-and-data-protection) | — |

_Also checked, not detected on this codebase: User registration, Password reset / change, JWT / bearer-token session, Session-token storage, Multi-factor authentication (TOTP / 2FA), OAuth / OIDC federated login._

<!-- §7.2 AUTH-MECHANISMS-FROZEN END -->

_Additional cataloged controls without a dedicated subsection (no implementation prose and no linked findings): Password-Based Authentication._

### 7.3 Session and Token Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.3 Session and Token Controls — Browser token storage, request propagation, token lifetime, revocation, cookie/session boundary. -->

_Additional cataloged controls without a dedicated subsection (no implementation prose and no linked findings): Session Management._

### 7.4 Authorization Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Role-Based Access Control](#role-based-access-control).

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.4 Authorization Controls — Route middleware, role checks, object-level authorization, client-side guards versus server-side enforcement. -->

<a id="role-based-access-control"></a>
#### 7.4.1 Role-Based Access Control

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-012](#f-012)
- [F-013](#f-013)

### 7.5 Query Construction and Data Access Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Parameterized Queries / ORM](#parameterized-queries-orm).

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.5 Query Construction and Data Access Controls — SQL/NoSQL query construction, ORM usage, parameter binding, selector and object ownership boundaries. -->

<a id="parameterized-queries-orm"></a>
#### 7.5.1 Parameterized Queries / ORM

**Status:** 🟡 Partial — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- No dedicated finding routed in this assessment.

### 7.6 Input Boundary Validation Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Validation Approach](#validation-approach), [Request Input Validation](#request-input-validation).

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.6 Input Boundary Validation Controls — Request schemas, parser limits, upload constraints, URL/path validation, business-rule boundaries. -->

<a id="validation-approach"></a>
#### 7.6.1 Validation Approach

**Status:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` / `🟡 Partial` / `🟠 Weak` / `🔴 Unsafe` / `🔴 Missing`, then add one clause stating the bottom line. present-but-broken → Unsafe; never-built → Missing. -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-011](#f-011)
- [F-018](#f-018)

<a id="input-validation"></a><a id="request-input-validation"></a>
#### 7.6.2 Request Input Validation

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-011](#f-011)
- [F-018](#f-018)

### 7.7 Output Encoding and Rendering Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.7 Output Encoding and Rendering Controls — Template escaping, DOM sinks, sanitizer bypasses, HTML rendering contexts. -->

_Additional cataloged controls without a dedicated subsection (no implementation prose and no linked findings): Output Encoding._

### 7.8 Browser and Cross-Origin Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Security Headers](#security-headers), [CORS Configuration](#cors-configuration).

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.8 Browser and Cross-Origin Controls — CSP, CORS, CSRF, Helmet/header hardening, browser-side request policy. -->

<a id="security-headers"></a><a id="security-headers-helmet"></a>
#### 7.8.1 Security Headers

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-004](#f-004)

<a id="cors-configuration"></a>
#### 7.8.2 CORS Configuration

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-004](#f-004)

### 7.9 Cryptography Secrets and Data Protection

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.9 Cryptography Secrets and Data Protection — Signing keys, HMAC/cookie secrets, password storage, data-at-rest protection. -->

_Additional cataloged controls without a dedicated subsection (no implementation prose and no linked findings): Password Hashing, Transport Layer Security._

### 7.10 File Parser and Outbound Request Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Rate Limiting](#rate-limiting).

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.10 File Parser and Outbound Request Controls — Uploads, archives, XML parsing, unsafe interpreters, SSRF, redirects, static or management-surface exposure. -->

<a id="rate-limiting"></a>
#### 7.10.1 Rate Limiting

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-009](#f-009)

### 7.11 Operations Runtime and Supply Chain Controls

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->

<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->
**Controls covered:** [Container Security Hardening](#container-security-hardening), [Dependency Pinning and SCA](#dependency-pinning-and-sca), [Automated SCA scanning](#automated-sca-scanning), [Automated dependency updates](#automated-dependency-updates), [Lockfile hygiene](#lockfile-hygiene).

**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->

**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §7.11 Operations Runtime and Supply Chain Controls — Audit logging, runtime/container hardening, dependency determinism, CI workflow permissions, package-install controls. -->

<a id="container-security-hardening"></a>
#### 7.11.1 Container Security Hardening

**Status:** 🔴 Unsafe — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-005](#f-005)
- [F-014](#f-014)

<a id="dependency-pinning-and-sca"></a>
#### 7.11.2 Dependency Pinning and SCA

**Status:** 🟠 Weak — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-005](#f-005)
- [F-014](#f-014)

<a id="automated-sca-scanning"></a>
#### 7.11.3 Automated SCA scanning

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-005](#f-005)
- [F-014](#f-014)

<a id="automated-dependency-updates"></a>
#### 7.11.4 Automated dependency updates

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-005](#f-005)
- [F-014](#f-014)

<a id="lockfile-hygiene"></a>
#### 7.11.5 Lockfile hygiene

**Status:** 🔴 Missing — <!-- NARRATIVE_PLACEHOLDER: one clause — the bottom line for this sub-control (what holds, or what is defeated and how). -->

<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. First sentence: what protection this control provides for the user, in business terms — no library, file, or route names. Second sentence: how the application implements it, naming the user-facing surface (e.g. 'authenticated endpoints', 'shopping basket routes', 'user profile pages') rather than file paths. Library / middleware / vendor names belong in the security-assessment block below, NOT in this implementation paragraph. POSITIVE-CASE only — what the mechanism does, not what is missing. -->

**Security assessment**

<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence in plain language describing what this codebase actually does or fails to do, then the concrete defects with file:line evidence. Library / middleware / vendor names are allowed here (this is the technical block), but should appear in the middle or end of the narrative, not as the first words. Multi-sentence prose — not a one-line inline tag like '**Security assessment:** ❌ Missing - …'. Avoid generic phrases ('an attacker could'); avoid rhetorical severity ('catastrophic'). -->

**Relevant findings**

- [F-005](#f-005)
- [F-014](#f-014)

### 7.12 Real-time and Not Applicable Controls

<!-- §7.12 LOCKED — mechanically derived from absence of real-time findings. Renderer must not rewrite the line below. -->
_Not applicable — no real-time / WebSocket findings routed to this category, and no AI/LLM, GraphQL, or gRPC surfaces detected by the recon scan. Controls catalogued elsewhere (container hardening, dependency determinism) are covered in their primary §7 sections._

### 7.13 Defense-in-Depth Summary

**Verdict:** <!-- NARRATIVE_PLACEHOLDER: one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. -->

<!-- §7.13 FORMAT — prose-only, NEVER a table. Two short paragraphs: (1) name the individual controls that exist and the strongest positive control if any (e.g. distroless runtime image, RS256 algorithm choice); (2) name which control-boundary repairs would restore layered defense (e.g. parameterized queries, runtime-injected secrets, strict JWT verification). Do NOT emit a Markdown table — `| header |` lines under §7.13 are a contract violation. Do NOT make speculative perimeter-absence claims (`No WAF`, `No firewall`, `No DAM`) — only positive evidence from the recon scan. -->

<!-- NARRATIVE_PLACEHOLDER: §7.13 Defense-in-Depth Summary — Cross-cutting summary of layered controls and residual architecture risk. (prose paragraphs only) -->
