## 9. Abuse Cases

_Abuse cases connect findings into attack scenarios. The verdict records whether repository evidence confirms the path. Combined risk is the highest policy-rated risk of the linked findings in the [§8 Findings Register](#8-findings-register); verification adds no severity. Within each verification group, higher-risk cases appear first. Equal risks use the strongest finding's assessed reach, impact and likelihood. Case IDs remain stable and do not indicate priority._

**Confirmed attack paths**

| # | Scenario | Actor | Combined Risk | Verdict |
|---|----------|-------|---------------|---------|
| [AC-T-005](#ac-t-005) | Authentication Bypass via Exposed Secret Material | Internet Attacker | 🔴 Critical | ⚠ Fully viable |
| [AC-B-001](#ac-b-001) | User reads or changes data of another user or tenant | attacker | 🟠 High | ⚠ Fully viable |
| [AC-T-007](#ac-t-007) | Privileged Action via Prompt Injection into a Tool-Calling Model | Internet Attacker | 🟠 High | ⚠ Fully viable |
| [AC-B-003](#ac-b-003) | User takes over another account | attacker | 🟡 Medium | ⚠ Fully viable |

**Unresolved scenarios**

| # | Scenario | Actor | Combined Risk | Verdict |
|---|----------|-------|---------------|---------|
| [AC-T-002](#ac-t-002) | Bulk Data Exfiltration via Broken Object Authorization | Internet Attacker | 🟠 High | ? Inconclusive |
| [AC-T-004](#ac-t-004) | Privilege Escalation via Mass-Assignment on Registration | Internet Attacker | 🟠 High | ? Inconclusive |
| [AC-T-001](#ac-t-001) | Account Takeover via XSS + Token Hijacking | Internet Attacker | 🟠 High | ? Inconclusive |
| [AC-B-004](#ac-b-004) | User bypasses a required approval | attacker | not rated (no linked finding) | ? Inconclusive |

**Checked without finding**

| Case | Result | Reason |
|------|--------|--------|
| <a id="ac-t-006"></a>AC-T-006 — Remote Code Execution via Server-Side Injection | ✗ Does not apply | The new Function() body is a fixed string ('return import(specifier)') and dynamicImport is only called with literals ('libxml2-wasm', 'libxml2-wasm/lib/nodejs.mjs'). The vm.runInContext script is also a constant. The attacker-controlled `d (`lib/xml.ts:12`) |

_Verdict: ⚠ Fully viable — no effective control blocks this chain · ◐ Partially blocked — at least one step has a compensating control but the chain is not fully closed · ✓ Mitigated — chain is broken at a verified step · ? Inconclusive — could not be verified end-to-end. Step: ✗ Refuted — the matched pairing does not hold on the code._

_Blocking mitigations: implementing any single mitigation listed under a case severs the chain at the named step, so the end-to-end abuse can no longer complete._

---

<a id="ac-t-005"></a>
### AC-T-005 — Authentication Bypass via Exposed Secret Material

> **Source:** technical abuse case · **Actor:** Internet Attacker — unauthenticated external attacker · **Combined Risk:** 🔴 Critical · **Verdict:** ⚠ Fully viable

**Goal:** Forge trusted tokens / credentials and impersonate any user.

**Prerequisite:** Signing material or other secrets are reachable (committed to a public repo, served by an unauthenticated route, or in an exposed directory).

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟠 [F-020](#f-020) — Hardcoded JWT private signing key in source | A private key, signing secret, or credential file is committed to the source repository or served without authentication. |
| 2 | 🟠 [F-018](#f-018) — Insecure JWT Verification | The exposed key/secret is the same one the server trusts, so a token signed with it (or the leaked credential) is accepted as authentic. |

**Scenario impact**

Exposed signing material collapses the entire authentication boundary: any attacker who reads the key can mint a valid token for any identity or role, with no credential ever required.

**Blocking mitigations**

- [M-040](#m-040) — Load JWT private key from secret store (**P2**): remediating 🟠 [F-020](#f-020) — Hardcoded JWT private signing key in source breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-038](#m-038) — Enforce JWT signature and algorithm verification (F-018) (**P2**): remediating 🟠 [F-018](#f-018) — Insecure JWT Verification breaks the chain at **Step 2**, removing the link the rest of the chain depends on.

---

<a id="ac-b-001"></a>
### AC-B-001 — User reads or changes data of another user or tenant

> **Source:** business abuse case · **Actor:** attacker · **Combined Risk:** 🟠 High · **Verdict:** ⚠ Fully viable

**Goal:** 

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟠 [F-003](#f-003) — Systemic IDOR Missing Ownership Checks | Check whether a user can read or change data that belongs to another user or tenant, through the primary operation or through an export, download, share link, search, or report. |

**Blocking mitigations**

- [M-030](#m-030) — Check basket ownership before returning it (**P2**): remediating 🟠 [F-003](#f-003) — Systemic IDOR Missing Ownership Checks breaks the chain at **Step 1**, removing the link the rest of the chain depends on.

---

<a id="ac-t-007"></a>
### AC-T-007 — Privileged Action via Prompt Injection into a Tool-Calling Model

> **Source:** technical abuse case · **Actor:** Internet Attacker — unauthenticated external attacker · **Combined Risk:** 🟠 High · **Verdict:** ⚠ Fully viable

**Goal:** Make the model invoke a privileged tool or return data the attacker is not entitled to, using the application's own authority.

**Prerequisite:** Attacker can place text into a conversation, document, or record that the application later sends to a language model.

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟡 [F-055](#f-055) — Client-supplied chat messages passed to model unvalidated | The handler builds the prompt by interpolating request or stored text into the same string as the system instructions, so attacker text is read as instruction. |
| 2 | 🟠 [F-042](#f-042) — Chatbot coupon tool lacks server-side discount limit | Tools exposed to the model run with the application's authority; a manipulated model turn therefore performs actions the caller could not. |

**Scenario impact**

Text an attacker can place anywhere the application later feeds to the model becomes instruction, and the tools behind that model run with the application's authority rather than the caller's — so a comment or a stored record reaches actions the attacker was never entitled to.

**Blocking mitigations**

- [M-070](#m-070) — Validate chat messages schema and allow user role only (**P3**): remediating 🟡 [F-055](#f-055) — Client-supplied chat messages passed to model unvalidated breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-057](#m-057) — Enforce correct server-side authorization (**P2**): remediating 🟠 [F-042](#f-042) — Chatbot coupon tool lacks server-side discount limit breaks the chain at **Step 2**, removing the link the rest of the chain depends on.

---

<a id="ac-b-003"></a>
### AC-B-003 — User takes over another account

> **Source:** business abuse case · **Actor:** attacker · **Combined Risk:** 🟡 Medium · **Verdict:** ⚠ Fully viable

**Goal:** 

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟡 [F-050](#f-050) — Unthrottled security-answer password reset | Check whether anyone other than the verified owner can change an account's credentials or recovery data, such as email, phone number, or reset tokens. |

**Blocking mitigations**

- [M-065](#m-065) — Rate limit and token-gate password reset (**P3**): remediating 🟡 [F-050](#f-050) — Unthrottled security-answer password reset breaks the chain at **Step 1**, removing the link the rest of the chain depends on.

---

<a id="ac-t-002"></a>
### AC-T-002 — Bulk Data Exfiltration via Broken Object Authorization

> **Source:** technical abuse case · **Actor:** Internet Attacker — authenticated low-privilege user · **Combined Risk:** 🟠 High · **Verdict:** ? Inconclusive

**Goal:** Enumerate and exfiltrate other users' records, then escalate own permissions via unguarded mass assignment.

**Prerequisite:** Attacker holds a valid, non-privileged user account.

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟠 [F-003](#f-003) — Systemic IDOR Missing Ownership Checks | Attacker enumerates and retrieves records for arbitrary object IDs; no ownership comparison is performed. |
| 2 | 🟠 [F-043](#f-043) — Role accepted from user registration body | Update endpoint persists an unfiltered `role` (or equivalent) field supplied in the request body. |

**Scenario impact**

The ownership gap exposes every record, and the mass-assignment gap lets the same low-privilege actor self-elevate — together they turn a single compromised account into full tenant data access and role escalation.

**Blocking mitigations**

- [M-030](#m-030) — Check basket ownership before returning it (**P2**): remediating 🟠 [F-003](#f-003) — Systemic IDOR Missing Ownership Checks breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-010](#m-010) — Manual review: verify Role accepted from user registration body (**P3**): remediating 🟠 [F-043](#f-043) — Role accepted from user registration body breaks the chain at **Step 2**, removing the link the rest of the chain depends on.
- [M-058](#m-058) — Allowlist client-controlled fields (**P2**): remediating 🟠 [F-043](#f-043) — Role accepted from user registration body breaks the chain at **Step 2**, removing the link the rest of the chain depends on.

---

<a id="ac-t-004"></a>
### AC-T-004 — Privilege Escalation via Mass-Assignment on Registration

> **Source:** technical abuse case · **Actor:** Internet Attacker — unauthenticated external attacker · **Combined Risk:** 🟠 High · **Verdict:** ? Inconclusive

**Goal:** Obtain an administrator account without any existing privilege.

**Prerequisite:** Self-registration is open (one unauthenticated POST).

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟠 [F-043](#f-043) — Role accepted from user registration body | The account-creation handler persists the request body wholesale, so a client-supplied `role` (or `isAdmin`) field is written verbatim. |

**Scenario impact**

A single unauthenticated request mints an admin account when the registration handler trusts a client-supplied role field — the most direct full-compromise path in role-based apps with open sign-up.

**Blocking mitigations**

- [M-010](#m-010) — Manual review: verify Role accepted from user registration body (**P3**): remediating 🟠 [F-043](#f-043) — Role accepted from user registration body breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-058](#m-058) — Allowlist client-controlled fields (**P2**): remediating 🟠 [F-043](#f-043) — Role accepted from user registration body breaks the chain at **Step 1**, removing the link the rest of the chain depends on.

---

<a id="ac-t-001"></a>
### AC-T-001 — Account Takeover via XSS + Token Hijacking

> **Source:** technical abuse case · **Actor:** Internet Attacker — unauthenticated external attacker · **Combined Risk:** 🟠 High · **Verdict:** ? Inconclusive

**Goal:** Obtain persistent authenticated access as an arbitrary user without valid credentials.

**Prerequisite:** Attacker can get markup rendered in a victim's session, through stored content (e.g. feedback, comments, profile fields) or a crafted link.

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | 🟠 [F-001](#f-001) — XSS via Trusted HTML Sanitizer Bypass | Attacker JavaScript executes in the victim's browser session. |
| 2 | 🟠 [F-110](#f-110) — Session token stored in web-accessible client storage | Token exfiltrated from local/session storage via the Step 1 payload. |
| 3 | _no matching finding_ | Exfiltrated token accepted for a new session; absence of token binding / PKCE removes the last server-side revocation opportunity. |

**Scenario impact**

Individually the XSS sink and the web-readable token storage rate below Critical, but chained they form a repeatable credential-theft path: a single stored payload causes indefinite session compromise for every user who views the affected page.

**Blocking mitigations**

- [M-028](#m-028) — Remove sanitizer bypass for feedback comments (**P2**): remediating 🟠 [F-001](#f-001) — XSS via Trusted HTML Sanitizer Bypass breaks the chain at **Step 1**, removing the link the rest of the chain depends on.
- [M-102](#m-102) — Store session tokens in HttpOnly cookies (**P2**): remediating 🟠 [F-110](#f-110) — Session token stored in web-accessible client storage breaks the chain at **Step 2**, removing the link the rest of the chain depends on.

---

<a id="ac-b-004"></a>
### AC-B-004 — User bypasses a required approval

> **Source:** business abuse case · **Actor:** attacker · **Combined Risk:** not rated (no linked finding) · **Verdict:** ? Inconclusive

**Goal:** 

**Attack chain**

| Step | Finding | Outcome |
|------|---------|---------|
| 1 | _no matching finding_ | Check whether a user can approve their own request where an independent approval is required, or change content after approval and keep the earlier approval. |

---

### Technical abuse cases — evaluated, not applicable

_These common abuse-case scenarios from the standard library were checked against this codebase and did not apply. They are listed so the assessment's abuse-case coverage is explicit, not silent._

| Scenario | Source | Why not applicable |
|----------|--------|--------------------|
| Privilege Escalation to Admin via JWT Algorithm Confusion | mandatory | no finding matched the required chain step(s) for this scenario |

---

### Business-case coverage

- 4 business abuse case(s) were not performed: exceeds the limit of 3 business abuse cases at standard depth.
