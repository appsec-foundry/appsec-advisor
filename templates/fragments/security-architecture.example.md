<!--
  security-architecture.example.md — STYLE ANCHOR for §6 H4 control blocks.

  Purpose
  -------
  This file is NOT a template that gets rendered. It is a style anchor the
  Stage 2 renderer agent (appsec-threat-renderer.md) Read()s before authoring
  `.fragments/security-architecture.md`. Every H4 control block in the final
  threat-model.md MUST follow the structural and linguistic patterns shown
  here. The blocks below are taken from the proven reference threat model
  for OWASP Juice Shop and represent the quality bar.

  Mandatory structure for every H4 control block (§6.2-§6.12)
  ----------------------------------------------------------
  1. `#### <Mechanism Name>` — name a real mechanism (e.g. "JWT Issuance",
     "Password Reset", "Query Construction"), NOT a taxonomy bucket
     ("JWT Authentication", "Password Hashing").
  2. **Positive intro paragraph** (≥ 25 words, 1-3 sentences) explaining
     what the mechanism IS and HOW it works in this codebase. Name the
     route, library, and components. NEVER open with "No", "None",
     "Missing", "Not implemented" — that belongs in the assessment.
  3. **Optional Mermaid `sequenceDiagram`** — include ONLY when the flow
     has ≥ 3 steps between ≥ 2 components AND prose alone would be
     unclear. Always introduce with ONE sentence ending in `:` such as
     "The diagram shows …:".
  4. `**Security assessment**` label followed by 2-4 sentences naming
     the concrete library, route, and `file:line` evidence. Multi-sentence
     prose — never a one-line `❌ Missing` tag.
  5. **Optional code excerpt** (≤ 6 lines) — include ONLY when the defect
     concentrates at one short location. Always introduce with ONE
     sentence ending in `:` such as "The vulnerable login lookup …:".
  6. `**Relevant findings**` label followed by a bullet list. Each bullet
     follows the form
     `- [F-NNN](#f-nnn) — <one sentence stating what this finding proves
     about the control>.` — never the title duplicated, never a span
     like `[F-001]…[F-005]`.

  Both Mermaid and code are OPTIONAL clarity aids. A pure-prose block
  is valid and common (see §6.8 Browser Security Headers in the
  reference). The mandatory elements are the intro paragraph, the
  assessment, and the findings bullet list.
-->

## Example 1 — Identity & Authentication, with diagram + code (the richest shape)

#### JWT Issuance

JWTs are issued by `lib/insecurity.ts:issueAuthToken()` after a successful password (or TOTP) verification. The helper signs a `{ id, email, role }` payload with the RSA private key under `lib/insecurity.ts:23`, sets a one-hour expiry, and returns the encoded token to the caller. Both `routes/login.ts` and `routes/2fa/verify.ts` use this single helper, so JWT format and lifetime are uniform across the API.

The diagram shows the positive issuance path from a verified user record to the encoded JWT returned to the browser:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant API as Login Route
    participant Issuer as issueAuthToken()
    participant Key as RSA Private Key

    User->>API: Successful credential check
    API->>Issuer: Sign payload {id, email, role}
    Issuer->>Key: Load private key
    Key-->>Issuer: PEM bytes
    Issuer-->>API: Encoded JWT (RS256, 1h)
    API-->>User: { token, basket_id, email }
```

**Security assessment**

The intended control is asymmetric signature on a short-lived token. That boundary is unsafe in this codebase because the private key is checked into the repository at `lib/insecurity.ts:23` and the verifier in `lib/insecurity.ts:57` accepts `alg:none` from older `express-jwt`. A correct issuance control would load the key from an external secret store and pin the verifier to `RS256` only.

The hardcoded key material that breaks the issuance boundary is plainly visible in the source:

```ts
export const privateKey =
  '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDNwqLEe...'
```

**Relevant findings**

- [F-001](#f-001) — Hardcoded RSA private key allows offline JWT forgery without breaking signing math.
- [F-002](#f-002) — `alg:none` acceptance lets an attacker drop the signature entirely.

---

## Example 2 — Identity & Authentication, with diagram, no code

#### Password Reset

Password reset is implemented as a single-step challenge: `POST /rest/user/reset-password` accepts `email`, the answer to a registered security question, and a new password. The route in `routes/resetPassword.ts` looks up the security question via the join with `SecurityAnswers`, compares the supplied answer, and updates the password column directly. No emailed token or rate-limit is involved.

The diagram shows the intended single-step reset path:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant SPA as Reset Form
    participant API as Reset Route
    participant DB as Users + SecurityAnswers

    User->>SPA: Enter email, security answer, new password
    SPA->>API: POST /rest/user/reset-password
    API->>DB: Lookup security answer for email
    DB-->>API: Stored answer hash
    API->>API: Compare supplied answer
    API->>DB: UPDATE Users SET password = hash(new)
    API-->>SPA: 200 OK
```

**Security assessment**

The reset boundary depends on the secrecy of the security answer alone. There is no out-of-band confirmation, no rate-limit, and the answer is stored with the same weak MD5 hash as passwords (`models/securityAnswer.ts:18`). A correct reset control would issue a single-use token over a verified channel and rate-limit attempts per account.

**Relevant findings**

- [F-014](#f-014) — Account takeover via guessable security answer; no rate-limit on the reset endpoint.
- [F-020](#f-020) — Unsalted MD5 weakens the answer hash that the reset relies on.

---

## Example 3 — Query Construction, no diagram, with code

#### Query Construction

Most data access goes through Sequelize models defined in `models/`, which generate parameterised queries by default. Two routes deviate: `routes/login.ts:34` and `routes/search.ts:23` construct raw SQL strings via `models.sequelize.query()`. Product review updates additionally accept a MarsDB selector under `routes/updateProductReviews.ts:24`, which makes the *structure* of the query user-controlled.

The product search route illustrates the raw-SQL construction pattern that bypasses the ORM:

```ts
models.sequelize.query(
  `SELECT * FROM Products WHERE (
     (name LIKE '%${criteria}%' OR description LIKE '%${criteria}%')
     AND deletedAt IS NULL
   ) ORDER BY name`
)
```

**Security assessment**

The control that should separate query structure from user-controlled values is missing on the login, search, and review-update paths. Each concatenates user input into either an SQL string or a MarsDB selector, allowing operator injection. A correct query-construction control would route every dynamic value through `?` bind parameters or a typed selector and reject anything that changes the query shape.

**Relevant findings**

- [F-003](#f-003) — SQL injection in the password login query allows authentication bypass.
- [F-004](#f-004) — SQL injection in product search enables data exfiltration.
- [F-011](#f-011) — NoSQL injection via user-controlled MarsDB selector on review updates.

---

## Example 4 — Pure-prose H4 (no diagram, no code) — valid when both would just repeat what prose already states

#### Browser Security Headers

Express applies a partial Helmet configuration in `server.ts:81` that enables `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `X-DNS-Prefetch-Control: off`. The set is applied globally before the API router is mounted. The Angular dev server does not add additional headers.

**Security assessment**

Helmet's defaults that ship without configuration are absent: `Content-Security-Policy`, `Strict-Transport-Security`, `Referrer-Policy`, and `Permissions-Policy` are not emitted. CSP in particular would constrain the impact of stored XSS in the search-result component. A correct browser-hardening control would enable Helmet's default profile and add a CSP allowlist tuned to the SPA's asset origins.

**Relevant findings**

- [F-031](#f-031) — Missing Content-Security-Policy header allows uncontrolled script execution from any reachable origin.
- [F-033](#f-033) — Missing Strict-Transport-Security header leaves HTTPS downgrade attacks viable on first contact.
