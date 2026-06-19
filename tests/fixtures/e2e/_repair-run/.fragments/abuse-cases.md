## 9. Abuse Cases

_Abuse cases describe end-to-end attack scenarios that chain individual findings into an exploitation path. Each case is **mandatory** — defined in the org profile / plugin library and evaluated against every repository. Every chain step references a finding from [§8 Findings Register](#8-findings-register); each step is code-confirmed against the repository and the chain verdict is folded deterministically from the per-step results, never rated by hand._

| # | Scenario | Actor | Combined Risk | Verdict |
|---|----------|-------|---------------|---------|
| [AC-T-001](#ac-t-001) | Account Takeover via Stored XSS + Token Hijacking | external-attacker | 🔴 Critical | ⚠ Fully viable |
| [AC-T-002](#ac-t-002) | Bulk Data Exfiltration via Broken Object Authorization | authenticated-user | 🔴 Critical | ? Inconclusive |
| [AC-T-003](#ac-t-003) | Privilege Escalation to Admin via JWT Algorithm Confusion | external-attacker | 🔴 Critical | ⚠ Fully viable |
| [AC-T-004](#ac-t-004) | Privilege Escalation via Mass-Assignment on Registration | external-attacker | 🔴 Critical | ⚠ Fully viable |
| [AC-T-005](#ac-t-005) | Authentication Bypass via Exposed Secret Material | external-attacker | 🔴 Critical | ⚠ Fully viable |
| [AC-T-006](#ac-t-006) | Remote Code Execution via Server-Side Injection | external-attacker | 🔴 Critical | ◐ Partially blocked |

_Verdict: ⚠ Fully viable — no effective control blocks this chain · ◐ Partially blocked — at least one step has a compensating control but the chain is not fully closed · ✓ Mitigated — chain is broken at a verified step · ? Inconclusive — could not be verified end-to-end._

---

### <a id="ac-t-001"></a>AC-T-001 — Account Takeover via Stored XSS + Token Hijacking

> **Source:** mandatory · **Actor:** external-attacker — unauthenticated external attacker · **Combined Risk:** 🔴 Critical · **Verdict:** ⚠ Fully viable

**Goal:** Obtain persistent authenticated access as an arbitrary user without valid credentials.

**Prerequisite:** Attacker can submit content that is later rendered to other users (e.g. feedback, comments, profile fields).

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟠 [F-020](#f-020) — Stored XSS in Product Descriptions — search-result.component.ts:132 | Attacker JavaScript executes in the victim's browser session. |
| 2 | 🟠 [F-001](#f-001) — JWT Bearer Token Stored in localStorage — login.component.ts:101 | Token exfiltrated from local/session storage via the Step 1 payload. |
| 3 | 🟠 [F-015](#f-015) — OAuth Implicit Flow Without State or PKCE — login.component.ts:134<br/>`lib/insecurity.ts:188` | Exfiltrated token accepted for a new session; absence of token binding / PKCE removes the last server-side revocation opportunity. |

**Why combined risk exceeds individual ratings**

Individually the XSS sink and the web-readable token storage rate below Critical, but chained they form a repeatable credential-theft path: a single stored payload causes indefinite session compromise for every user who views the affected page.

**Blocking mitigations**

Implementing any single mitigation below severs the chain at the named step, so the end-to-end abuse can no longer complete:

- [M-030](#m-030) — Encode output instead of bypassing the framework sanitizer (**P2**): remediating 🟠 [F-020](#f-020) — Stored XSS in Product Descriptions — search-result.component.ts:132 breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-011](#m-011) — Store session tokens in HttpOnly, Secure cookies (**P3**): remediating 🟠 [F-001](#f-001) — JWT Bearer Token Stored in localStorage — login.component.ts:101 breaks the chain at **Step 2**, removing the link the rest of the chain depends on.
- [M-025](#m-025) — Replace OAuth Implicit Flow with Authorization Code Flow with PKCE and state validation (**P2**): remediating 🟠 [F-015](#f-015) — OAuth Implicit Flow Without State or PKCE — login.component.ts:134 breaks the chain at **Step 3**, removing the link the rest of the chain depends on.

---

### <a id="ac-t-002"></a>AC-T-002 — Bulk Data Exfiltration via Broken Object Authorization

> **Source:** mandatory · **Actor:** authenticated-user — authenticated low-privilege user · **Combined Risk:** 🔴 Critical · **Verdict:** ? Inconclusive

**Goal:** Enumerate and exfiltrate other users' records, then escalate own permissions via unguarded mass assignment.

**Prerequisite:** Attacker holds a valid, non-privileged user account.

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🔴 [F-007](#f-007) — Insecure Direct Object Reference — routes/address.ts:11<br/>`routes/basket.ts:19` | Attacker enumerates and retrieves records for arbitrary object IDs; no ownership comparison is performed. |
| 2 | 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30 | Update endpoint persists an unfiltered `role` (or equivalent) field supplied in the request body. |

**Why combined risk exceeds individual ratings**

The ownership gap exposes every record, and the mass-assignment gap lets the same low-privilege actor self-elevate — together they turn a single compromised account into full tenant data access and role escalation.

**Blocking mitigations**

Implementing any single mitigation below severs the chain at the named step, so the end-to-end abuse can no longer complete:

- [M-017](#m-017) — Enforce object-level (ownership) authorization (**P1**): remediating 🔴 [F-007](#f-007) — Insecure Direct Object Reference — routes/address.ts:11 breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-013](#m-013) — Move secrets to a managed secret store (**P2**): remediating 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30 breaks the chain at **Step 2**, removing the link the rest of the chain depends on.

---

### <a id="ac-t-003"></a>AC-T-003 — Privilege Escalation to Admin via JWT Algorithm Confusion

> **Source:** mandatory · **Actor:** external-attacker — unauthenticated external attacker · **Combined Risk:** 🔴 Critical · **Verdict:** ⚠ Fully viable

**Goal:** Forge an admin-role JWT without knowledge of the signing secret.

**Prerequisite:** Attacker can obtain any valid JWT issued by the system (e.g. by registering a free account).

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🔴 [F-005](#f-005) — Hardcoded RSA Private Key Enables Universal JWT Forgery — lib/insecurity.ts:23 | Verifier accepts attacker-chosen `alg` (e.g. `none` or HMAC-with-public-key), allowing token re-signing without the secret. |
| 2 | 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30<br/>`lib/insecurity.ts:159` | Forged `role: admin` claim is accepted as authoritative because the role is not re-fetched from the database per request. |

**Why combined risk exceeds individual ratings**

Algorithm confusion alone yields a forgeable token; trusting the in-token role claim turns that forgery into instant admin access — neither gap is Critical in isolation, but the chain is a full authentication bypass.

**Blocking mitigations**

Implementing any single mitigation below severs the chain at the named step, so the end-to-end abuse can no longer complete:

- [M-015](#m-015) — Move cryptographic keys to a managed secret store (**P1**): remediating 🔴 [F-005](#f-005) — Hardcoded RSA Private Key Enables Universal JWT Forgery — lib/insecurity.ts:23 breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-013](#m-013) — Move secrets to a managed secret store (**P2**): remediating 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30 breaks the chain at **Step 2**, removing the link the rest of the chain depends on.

---

### <a id="ac-t-004"></a>AC-T-004 — Privilege Escalation via Mass-Assignment on Registration

> **Source:** mandatory · **Actor:** external-attacker — unauthenticated external attacker · **Combined Risk:** 🔴 Critical · **Verdict:** ⚠ Fully viable

**Goal:** Obtain an administrator account without any existing privilege.

**Prerequisite:** Self-registration is open (one unauthenticated POST).

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30<br/>`server.ts:483` | The account-creation handler persists the request body wholesale, so a client-supplied `role` (or `isAdmin`) field is written verbatim. |

**Why combined risk exceeds individual ratings**

A single unauthenticated request mints an admin account when the registration handler trusts a client-supplied role field — the most direct full-compromise path in role-based apps with open sign-up.

**Blocking mitigations**

Implementing any single mitigation below severs the chain at the named step, so the end-to-end abuse can no longer complete:

- [M-013](#m-013) — Move secrets to a managed secret store (**P2**): remediating 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30 breaks the chain at **Step 1**, removing the link the rest of the chain depends on.

---

### <a id="ac-t-005"></a>AC-T-005 — Authentication Bypass via Exposed Secret Material

> **Source:** mandatory · **Actor:** external-attacker — unauthenticated external attacker · **Combined Risk:** 🔴 Critical · **Verdict:** ⚠ Fully viable

**Goal:** Forge trusted tokens / credentials and impersonate any user.

**Prerequisite:** Signing material or other secrets are reachable (committed to a public repo, served by an unauthenticated route, or in an exposed directory).

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30<br/>`lib/insecurity.ts:23` | A private key, signing secret, or credential file is committed to the source repository or served without authentication. |
| 2 | 🔴 [F-005](#f-005) — Hardcoded RSA Private Key Enables Universal JWT Forgery — lib/insecurity.ts:23 | The exposed key/secret is the same one the server trusts, so a token signed with it (or the leaked credential) is accepted as authentic. |

**Why combined risk exceeds individual ratings**

Exposed signing material collapses the entire authentication boundary: any attacker who reads the key can mint a valid token for any identity or role, with no credential ever required.

**Blocking mitigations**

Implementing any single mitigation below severs the chain at the named step, so the end-to-end abuse can no longer complete:

- [M-013](#m-013) — Move secrets to a managed secret store (**P2**): remediating 🔴 [F-003](#f-003) — OAuth Derived Password from Email Enables Credential — oauth.component.ts:30 breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-015](#m-015) — Move cryptographic keys to a managed secret store (**P1**): remediating 🔴 [F-005](#f-005) — Hardcoded RSA Private Key Enables Universal JWT Forgery — lib/insecurity.ts:23 breaks the chain at **Step 2**, removing the link the rest of the chain depends on.

---

### <a id="ac-t-006"></a>AC-T-006 — Remote Code Execution via Server-Side Injection

> **Source:** mandatory · **Actor:** external-attacker — unauthenticated external attacker · **Combined Risk:** 🔴 Critical · **Verdict:** ◐ Partially blocked

**Goal:** Execute arbitrary code in the application process.

**Prerequisite:** An input reaches a server-side interpreter / template / eval.

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🔴 [F-011](#f-011) — JavaScript Sandbox Escape — routes/b2bOrder.ts:23 | Attacker-controlled input is passed to `eval`, a server-side template engine, an unsafe sandbox, or an unsafe deserializer. |

**Why combined risk exceeds individual ratings**

A single injection into a server-side interpreter yields code execution in the application process — the highest-impact outcome, granting full filesystem and network access from one unauthenticated request.

**Blocking mitigations**

Implementing any single mitigation below severs the chain at the named step, so the end-to-end abuse can no longer complete:

- [M-021](#m-021) — Remove server-side evaluation of untrusted input (**P1**): remediating 🔴 [F-011](#f-011) — JavaScript Sandbox Escape — routes/b2bOrder.ts:23 breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
