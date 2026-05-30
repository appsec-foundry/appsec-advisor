# Threat Register — compact card ("Kachel") layout

**Goal:** render §8 Threat Register as compact cards in the §9 Mitigation-Register
style, instead of one giant table whose cells each hold a full 8-field Story Card.
**Nothing is changed in the plugin yet** — this is the worked-out design with the
real juice-shop findings rendered so the look can be judged directly.

## Card anatomy

```
<a id="t-NNN"></a><a id="f-NNN"></a>
<sev> **F-NNN · <Short Title>**  ·  [C-NN](#c-nn) <Component>  ·  `file:line`
                                              ↑ blank line = small gap from the title
**Issue:** <1–2 sentences; fold the sharpest impact in as "→ <consequence>">.<br>
**Fix:** [M-NNN](#m-nnn) — <short mitigation title>.<br>
<sub><Classification> · CWE-NNN · OWASP A0X · evidence <✓|◌|⚠>[ · [walkthrough §3.x](#)]</sub>

<details><summary>Evidence · <code>file:line</code></summary>     ← only when a snippet exists

…fenced code…
</details>
```

Rules:
- **Title line** = severity emoji + `F-NNN · Title` + component link + `file:line`, all on one line.
- **Blank line after the title** gives the small visual gap before the body.
- **Issue and Fix are always separate lines** (hard-broken with `<br>`), each bold-labelled.
- **Impact** is not its own line — its sharpest clause folds into the Issue sentence as
  `→ <consequence>` (drops today's redundant one-liners like "No ownership validation.").
- **Footer** `<sub>` carries the metadata on one greyed line: Classification · CWE · OWASP ·
  evidence badge (`✓` verified · `◌` ambiguous · `⚠` refuted) · optional walkthrough link ·
  optional `*(raw Critical)*` cap note.
- **No mapped mitigation** → `**Fix:** _none mapped — see [§9](#9-mitigation-register)_.` so
  every card keeps the same two-line body.
- **Multiple mitigations** → show the primary `M-NNN` on the card; the rest stay in §9.
- **Code/evidence** goes in a closed `<details>` so the card face stays ~4 lines; omitted when
  there is no snippet.
- **Grouping & order:** `### <emoji> <Criticality> (<count>)` headers, severity desc
  (🔴 → 🟠 → 🟡 → 🟢); within a group keep the current vektor sort.

Result: today's ~15–25-line rows become ~4-line cards (+ an optional fold), and the section
reads as a matched pair with §9. No CSS is used (GitHub/GitLab strip it) — only `<a id>`,
`<sub>`, `<details>` and emoji badges, all already in the document, so it renders identically
everywhere and keeps every anchor and cross-link.

---

## Rendered sample (real juice-shop findings)

The cards below are the *actual* §8 data re-laid-out. A representative subset is shown — the
remaining High/Medium findings follow the identical pattern.

### 🔴 Critical (6)

<a id="t-001"></a><a id="f-001"></a>
🔴 **F-001 · SQL Injection**  ·  [C-01](#c-01) Express Backend API  ·  `routes/login.ts:36`

**Issue:** Login assembles raw SQL by interpolating `req.body.email`; a crafted `' OR 1=1--` resolves to a tautology → returns the first user (admin) without a password.<br>
**Fix:** [M-001](#m-001) — Parameterize all SQL queries (replace string interpolation).<br>
<sub>Injection · CWE-89 · OWASP A03 · evidence ✓ · [walkthrough §3.1](#31-sql-injection-authentication-bypass-via-login-route)</sub>

<details><summary>Evidence · <code>routes/login.ts:36</code></summary>

```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' …`)
```
</details>

<a id="t-002"></a><a id="f-002"></a>
🔴 **F-002 · Hardcoded RSA Key**  ·  [C-01](#c-01) Express Backend API  ·  `lib/insecurity.ts:24`

**Issue:** The 1024-bit RSA key that signs all JWTs is committed in plaintext → anyone with the (public) source forges admin tokens offline, no runtime bug needed.<br>
**Fix:** [M-002](#m-002) — Move the key to an injected secret and rotate it.<br>
<sub>Cryptographic Failures · CWE-321 · OWASP A02 · evidence ◌ ambiguous · [walkthrough §3.2](#32-jwt-forgery-hardcoded-rsa-private-key-in-source)</sub>

<a id="t-004"></a><a id="f-004"></a>
🔴 **F-004 · Code Injection (eval)**  ·  [C-01](#c-01) Express Backend API  ·  `routes/userProfile.ts:57`

**Issue:** The profile route runs `eval(code)` on the `#{…}` portion of a username → `#{process.mainModule.require('child_process').execSync('id')}` executes arbitrary server-side code.<br>
**Fix:** [M-003](#m-003) — Remove `eval()`; use a data-only execution path.<br>
<sub>Code Execution via Unsafe Eval · CWE-94 · OWASP A08 · evidence ✓ · [walkthrough §3.4](#34-remote-code-execution-eval-on-user-controlled-username)</sub>

<details><summary>Evidence · <code>routes/userProfile.ts:57</code></summary>

```typescript
const code = username?.substring(2, username.length - 1)
// …later…
eval(code)
```
</details>

> _F-003 (SQL Injection · search), F-015 (MD5 password hashing), F-023 (schema disclosure via UNION) render the same way and are omitted here._

### 🟠 High (17)

<a id="t-016"></a><a id="f-016"></a>
🟠 **F-016 · JWT in localStorage**  ·  [C-02](#c-02) Angular SPA Frontend  ·  `request.interceptor.ts:13`

**Issue:** The JWT is stored in `localStorage`, readable by any injected script → XSS hijacks the session for the full 6-hour token lifetime with no server-side revocation.<br>
**Fix:** [M-011](#m-011) — Move JWT storage to an httpOnly cookie.<br>
<sub>Insecure Client-Side Storage · CWE-922 · OWASP A02 · evidence ✓</sub>

<a id="t-009"></a><a id="f-009"></a>
🟠 **F-009 · Code Injection (B2B safeEval)**  ·  [C-05](#c-05) B2B Order API  ·  `routes/b2bOrder.ts:19`

**Issue:** The B2B endpoint passes attacker-controlled `orderLinesData` to `safeEval`; the `notevil` library is not a real sandbox → prototype-pollution / escape sequences achieve RCE.<br>
**Fix:** [M-003](#m-003) — Replace eval with structured JSON-schema validation.<br>
<sub>Code Execution via Unsafe Eval · CWE-94 · OWASP A08 · evidence ✓ · *(raw Critical)*</sub>

<details><summary>Evidence · <code>routes/b2bOrder.ts:19</code></summary>

```typescript
const orderLinesData = body.orderLinesData || ''
const sandbox = { safeEval, orderLinesData }
```
</details>

<a id="t-012"></a><a id="f-012"></a>
🟠 **F-012 · Uncontrolled Recursion (ReDoS)**  ·  [C-01](#c-01) Express Backend API  ·  `lib/insecurity.ts:65`

**Issue:** `sanitizeSecure()` re-invokes itself until the input stabilises → crafted input that alternates each pass causes infinite recursion and stack-overflow DoS.<br>
**Fix:** _none mapped — see [§9](#9-mitigation-register)._<br>
<sub>Denial of Service · CWE-400 · OWASP A04 · evidence ✓</sub>

> _The remaining 14 High findings (F-005 XXE, F-006 SSRF, F-007 directory listing, F-008 ZIP traversal, F-010 open redirect, F-013 NoSQL DoS, F-014 IDOR, F-017 stored XSS, F-020 DOM XSS, F-021 mass-assignment, F-022 user-table disclosure, F-024 FTP authz, F-025 YAML deserialization, F-026 XXE DoS) follow the identical pattern._

### 🟡 Medium (3)

<a id="t-011"></a><a id="f-011"></a>
🟡 **F-011 · Insufficient Security Logging**  ·  [C-01](#c-01) Express Backend API  ·  `server.ts:350`

**Issue:** Only `morgan` HTTP logging is present — no security-event logging for auth failures, injection attempts or privilege escalation → attackers recon undetected.<br>
**Fix:** [M-008](#m-008) — Add security-event logging for auth and injection events.<br>
<sub>Missing Audit Logging · CWE-778 · OWASP A09 · evidence ◌ ambiguous</sub>

<a id="t-018"></a><a id="f-018"></a>
🟡 **F-018 · Client-Side Info Disclosure**  ·  [C-02](#c-02) Angular SPA Frontend  ·  `score-board.component.ts:86`

**Issue:** The score board loads all challenge metadata (names, hints, solution flags) client-side → full challenge enumeration without completion.<br>
**Fix:** _none mapped — see [§9](#9-mitigation-register)._<br>
<sub>Error Information Disclosure · CWE-200 · OWASP A05 · evidence ✓</sub>

---

## If you want to build it (pointers, no changes here)

- New renderer `_render_threat_register_cards` + template `threat-register-cards.md.j2`,
  selected by a contract flag (e.g. `threat_register_layout: cards | table`) so the table
  stays available for tooling and quick depth.
- Reuse the existing Story-Card field extraction — only the *emit* step changes (title line +
  `<br>`-separated Issue/Fix + `<sub>` footer + optional `<details>`).
- Keep the section header block (Risk Distribution / STRIDE Coverage) above the cards.
- QA: §8 link/anchor invariants (`[F-NNN](#f-nnn)`, component/mitigation links) apply
  unchanged; add a card-structure check mirroring the §9 block checks.
