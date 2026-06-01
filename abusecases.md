## 9. Abuse Cases

_Abuse cases describe end-to-end attack scenarios that span multiple components or require chaining of individual vulnerabilities. Each case is either **mandatory** (defined in the org profile, evaluated against every repository) or **discovered** (synthesized from the threat register by the threat analysis). All chain steps reference verified findings from [§8 Threat Register](#8-threat-register) — no step is asserted without a corresponding T-ID._

| # | Scenario | Actor | Combined Risk | Verdict |
|---|----------|-------|---------------|---------|
| [AC-001](#ac-001) | Account Takeover via Stored XSS + Token Hijacking | External attacker | 🔴 Critical | ⚠ Fully viable |
| [AC-002](#ac-002) | Bulk Data Exfiltration via IDOR + Mass Assignment | Authenticated user | 🟠 High | ◐ Partially blocked |
| [AC-003](#ac-003) | Privilege Escalation to Admin via JWT Algorithm Confusion | External attacker | 🔴 Critical | ✓ Mitigated |

_Verdict: ⚠ Fully viable — no effective control blocks this chain · ◐ Partially blocked — at least one step has a compensating control but the chain is not fully closed · ✓ Mitigated — chain is broken at a verified step_

---

### AC-001 — Account Takeover via Stored XSS + Token Hijacking

> **Source:** org-profile `ACT-01` (mandatory) · **Actor:** ACT-E-01 — unauthenticated external attacker · **Combined Risk:** 🔴 Critical · **Verdict:** ⚠ Fully viable

**Goal:** Obtain persistent authenticated access as an arbitrary user without valid credentials.

**Prerequisite:** Attacker can submit content that is later rendered to other users (e.g., feedback, comments, profile fields).

**Attack chain**

| Step | Finding | Evidence | Outcome |
|------|---------|----------|---------|
| 1 | [T-048](#t-048) — Stored XSS via `bypassSecurityTrustHtml()` | `about.component.ts:119` | Attacker JavaScript executes in the victim's browser session |
| 2 | [T-046](#t-046) — Refresh token persisted in `localStorage` | `request.interceptor.ts:13` | Token exfiltrated from `localStorage` via Step 1 payload |
| 3 | [T-045](#t-045) — OAuth implicit flow without PKCE | `oauth.component.ts:23` | Exfiltrated token accepted for a new session; attacker gains indefinite access |

**Why combined risk exceeds individual ratings**

T-048 rates 🟠 High (impact scoped to feedback-rendering context). T-046 rates 🟡 Medium (token exposure requires an active XSS precondition). Chained, they form a repeatable credential-theft path: a single stored payload in `/api/Feedbacks` causes indefinite session compromise for every user who views the affected page. The PKCE absence in Step 3 removes the last server-side opportunity to invalidate the exfiltrated token. No additional attacker capability beyond an initial POST to `/api/Feedbacks` is required.

**Blocking mitigations**

| Mitigation | Addresses | Breaks chain at |
|---|---|---|
| [M-007](#m-007) — Replace `bypassSecurityTrustHtml()` with `DomSanitizer` · **P1** | [T-048](#t-048) | Step 1 |
| [M-009](#m-009) — Migrate token storage to `HttpOnly` session cookie · **P1** | [T-046](#t-046) | Step 2 |

Fixing either M-007 or M-009 breaks the chain. Both should be addressed: M-007 eliminates the injection vector; M-009 limits the blast radius of any future XSS that bypasses the sanitizer.

---

### AC-002 — Bulk Data Exfiltration via IDOR + Mass Assignment

> **Source:** analysis-discovered · **Confidence:** medium · **Actor:** ACT-I-01 — authenticated insider or compromised user account · **Combined Risk:** 🟠 High · **Verdict:** ◐ Partially blocked

**Goal:** Exfiltrate another user's profile and order data, then escalate own account permissions via unguarded mass assignment.

**Prerequisite:** Attacker holds a valid, non-privileged user account.

**Attack chain**

| Step | Finding | Evidence | Outcome |
|------|---------|----------|---------|
| 1 | [T-012](#t-012) — IDOR on `GET /api/Users/:id` — no ownership check | `routes/user.ts:44` | Attacker enumerates and retrieves profile records for arbitrary user IDs |
| 2 | [T-019](#t-019) — Mass assignment on `PUT /api/Users/:id` — `role` field not filtered | `routes/user.ts:88` | Attacker sends `{"role":"admin"}` in update body; field persisted without authorisation check |

**Why partially blocked**

Step 1 is fully viable: the ownership check is absent (`routes/user.ts:44` performs no `req.user.id === params.id` comparison). Step 2 is partially blocked: the application does not validate `role` on input, but a separate middleware (`auth.middleware.ts:31`) asserts `req.user.role === 'admin'` on write-sensitive downstream routes. The attacker cannot immediately leverage the elevated role without a request that bypasses this middleware check — no bypass is currently known. The chain is therefore incomplete but high-priority: the T-019 closure depends on an assumption enforced only in middleware, not at the model layer, and a future middleware regression would make the chain fully viable.

**Blocking mitigations**

| Mitigation | Addresses | Breaks chain at |
|---|---|---|
| [M-014](#m-014) — Add ownership assertion in `getUserById()` · **P2** | [T-012](#t-012) | Step 1 |
| [M-015](#m-015) — Allowlist permitted update fields; strip `role` at DTO layer · **P1** | [T-019](#t-019) | Step 2 |

---

### AC-003 — Privilege Escalation to Admin via JWT Algorithm Confusion

> **Source:** org-profile `ACT-03` (mandatory) · **Actor:** ACT-E-01 — unauthenticated external attacker · **Combined Risk:** 🔴 Critical (at time of discovery) · **Verdict:** ✓ Mitigated

**Goal:** Forge an admin-role JWT without knowledge of the signing secret.

**Prerequisite:** Attacker can obtain any valid JWT issued by the system (e.g., by registering a free account).

**Attack chain**

| Step | Finding | Evidence | Outcome | Status |
|------|---------|----------|---------|--------|
| 1 | [T-003](#t-003) — JWT `alg` field not validated on verification | `middleware/auth.ts:57` | Attacker re-signs token with `alg: none`; server accepts it | ✓ Resolved — `jsonwebtoken` pinned to `RS256` (v2.3.1) |
| 2 | [T-004](#t-004) — `role` claim not re-fetched from DB on each request | `middleware/auth.ts:61` | Forged `role: admin` claim in JWT payload accepted as authoritative | ✓ Resolved — role re-fetched from DB per request (PR #214) |

**Chain status**

Both steps were verified as exploitable in v1 assessment (2026-03-10). Both are confirmed resolved as of v2 (2026-04-19): T-003 via `jsonwebtoken` algorithm pinning, T-004 via DB-backed role lookup on every request. This case is retained in the report because it is mandatory in the org profile (`ACT-03`) and the resolution must be explicitly confirmed per run, not assumed carried forward.

See [§10 Out of Scope](#10-out-of-scope) for the accepted-risk entry and PR references.
