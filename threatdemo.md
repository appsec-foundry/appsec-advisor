# Threat Register — compact card ("Kachel") layout

**Goal:** render §8 Threat Register as compact, uniform cards that mirror the §9
Mitigation-Register block style, instead of one giant table whose cells each hold a
full Story Card. **Nothing is changed in the plugin yet** — this is the worked-out
design with all 26 real juice-shop findings rendered so the look can be judged directly.

## Design principle

A register reads as *structured* when **every entry has the same fields, in the same
order, with the same labels** — what makes §9 clean. Each threat card has one fixed
skeleton; nothing about its shape varies finding-to-finding:

```
<a id="t-NNN"></a><a id="f-NNN"></a>
#### F-NNN · <Short Title>

**Severity:** <emoji> <Word>  ·  **Component:** [C-NN](#c-nn) <Name>  ·  **Location:** `file:line`
**Issue:** <1–2 sentences; sharpest impact folded in as "→ <consequence>">
**Root cause:** <the systemic control failure behind it — one phrase>
**Evidence:** <✓|◌|⚠> <verified|ambiguous|refuted> — <one sentence: what in the code proves it>.
`<short inline snippet — a few lines, not collapsed>`
**Fix:** <the remediation in a few plain words> → [M-NNN](#m-nnn)
**Classification:** <Category> · [CWE-NNN](https://cwe.mitre.org/data/definitions/NNN.html) · [OWASP A0X:2021](https://owasp.org/Top10/A0X_2021/)
```

Fixed rules (no per-card variation):
- **Six labelled fields, always in this order:** `Severity/Component/Location` → `Issue` →
  `Root cause` → `Evidence` → `Fix` → `Classification`. `Classification` is always last.
- **Root cause** is the systemic weakness (derived from the finding's attack-class — findings
  that share a class share the root cause, which is the point of root-cause grouping); it is
  *not* a restatement of the Issue.
- **Evidence** = verification glyph + one sentence, then (if any) a short inline snippet — no
  `<details>` fold, and it does **not** re-link the `Location` (already in the meta line).
- **Fix** = the remedy in a few plain words first, *then* the mitigation link (`… → [M-NNN]`);
  unmapped findings use `… → _not yet mapped ([§9](#9-mitigation-register))_`.
- **Classification** links CWE and OWASP **externally** (cwe.mitre.org / owasp.org); an optional
  `· walkthrough [§3.x](#)` tail is the only thing that may follow.
- **Severity** carries an inline `_(raw Critical)_` note when triage capped it.
- **Group by severity** (`### 🔴 Critical (n)`, desc 🔴→🟠→🟡→🟢), mirroring §9's priority groups.

No CSS is used (GitHub/GitLab strip it) — only `<a id>`, markdown links and emoji badges — so
every internal anchor and external reference is preserved.

---

## §8 Threat Register

**Risk:** 🔴 Critical 6 · 🟠 High 17 · 🟡 Medium 3 · 🟢 Low 0 — **26 findings**
**Evidence:** ✓ verified · ◌ ambiguous · ⚠ refuted (re-checked by the Phase-10a verifier)

### 🔴 Critical (6)

<a id="t-002"></a><a id="f-002"></a>
#### F-002 · Hardcoded RSA Key

**Severity:** 🔴 Critical  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `lib/insecurity.ts:24`
**Issue:** The 1024-bit RSA key that signs all JWTs is committed in plaintext → anyone with the (public) source forges admin tokens offline, no runtime bug needed.
**Root cause:** Secret material lives in version-controlled source instead of a runtime secret store.
**Evidence:** ◌ ambiguous — the signing key is embedded as a literal constant in source rather than loaded from a secret store.
`const privateKey = '-----BEGIN RSA PRIVATE KEY-----\nMIICX…'`
**Fix:** Move the signing key into an injected secret and rotate it → [M-002](#m-002)
**Classification:** Cryptographic Failures · [CWE-321](https://cwe.mitre.org/data/definitions/321.html) · [OWASP A02:2021](https://owasp.org/Top10/A02_2021/) · walkthrough [§3.2](#)

<a id="t-001"></a><a id="f-001"></a>
#### F-001 · SQL Injection (login)

**Severity:** 🔴 Critical  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/login.ts:36`
**Issue:** Login interpolates `req.body.email` into raw SQL; a crafted `' OR 1=1--` resolves to a tautology → returns the first user (admin) without a password.
**Root cause:** User input reaches the SQL interpreter without parameter binding.
**Evidence:** ✓ verified — the query string is built by interpolating untrusted input instead of binding parameters.
``sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' …`)``
**Fix:** Bind parameters instead of interpolating input into SQL → [M-001](#m-001)
**Classification:** Injection · [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · [OWASP A03:2021](https://owasp.org/Top10/A03_2021/) · walkthrough [§3.1](#)

<a id="t-003"></a><a id="f-003"></a>
#### F-003 · SQL Injection (search)

**Severity:** 🔴 Critical  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/search.ts:24`
**Issue:** Product search interpolates the `q` parameter into raw SQL → UNION attacks exfiltrate user credentials and the full database schema.
**Root cause:** User input reaches the SQL interpreter without parameter binding.
**Evidence:** ✓ verified — the `LIKE` clause concatenates the search term directly into the SQL text.
``sequelize.query(`… name LIKE '%${criteria}%' …`)``
**Fix:** Bind parameters instead of interpolating input into SQL → [M-001](#m-001)
**Classification:** Injection · [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · [OWASP A03:2021](https://owasp.org/Top10/A03_2021/) · walkthrough [§3.3](#)

<a id="t-004"></a><a id="f-004"></a>
#### F-004 · Code Injection (eval)

**Severity:** 🔴 Critical  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/userProfile.ts:57`
**Issue:** The profile route runs `eval()` on the `#{…}` portion of a username → `#{…execSync('id')}` executes arbitrary server-side code.
**Root cause:** Untrusted input is treated as executable code at a runtime evaluator.
**Evidence:** ✓ verified — a substring of the username is handed straight to the runtime evaluator.
`const code = username.substring(2, username.length - 1); eval(code)`
**Fix:** Drop `eval`; compute via a data-only path → [M-003](#m-003)
**Classification:** Code Execution via Unsafe Eval · [CWE-94](https://cwe.mitre.org/data/definitions/94.html) · [OWASP A08:2021](https://owasp.org/Top10/A08_2021/) · walkthrough [§3.4](#)

<a id="t-015"></a><a id="f-015"></a>
#### F-015 · MD5 Password Hashing

**Severity:** 🔴 Critical  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `lib/insecurity.ts:43`
**Issue:** All user passwords are hashed with unsalted MD5 → a database breach cracks every password near-instantly via rainbow tables / GPU.
**Root cause:** Passwords are protected with a fast, unsalted hash instead of a slow KDF.
**Evidence:** ✓ verified — a single-pass, unsalted hash function is used for password storage.
`return crypto.createHash('md5').update(password).digest('hex')`
**Fix:** Hash with a salted, slow KDF (bcrypt / Argon2id) → [M-010](#m-010)
**Classification:** Cryptographic Failures · [CWE-916](https://cwe.mitre.org/data/definitions/916.html) · [OWASP A02:2021](https://owasp.org/Top10/A02_2021/) · walkthrough [§3.5](#)

<a id="t-023"></a><a id="f-023"></a>
#### F-023 · SQL Injection (schema disclosure)

**Severity:** 🔴 Critical  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/search.ts:46`
**Issue:** The search SQLi runs `SELECT sql FROM sqlite_master` → full schema disclosure, a complete roadmap for follow-on exploitation.
**Root cause:** User input reaches the SQL interpreter without parameter binding.
**Evidence:** ✓ verified — UNION-injected input reaches the query that reads the schema catalogue.
`sequelize.query('SELECT sql FROM sqlite_master')`
**Fix:** Bind parameters instead of interpolating input into SQL → [M-001](#m-001)
**Classification:** Injection · [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · [OWASP A03:2021](https://owasp.org/Top10/A03_2021/) · walkthrough [§3.6](#)

### 🟠 High (17)

<a id="t-005"></a><a id="f-005"></a>
#### F-005 · XML External Entity (XXE)

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/fileUpload.ts:82`
**Issue:** XML uploads are parsed with libxmljs2 `noent:true` → an external-entity payload reads arbitrary files such as `file:///etc/passwd`.
**Root cause:** The XML parser resolves external entities on untrusted documents.
**Evidence:** ✓ verified — the parser is configured to expand external entities on untrusted input.
`libxml.parseXml(data, { noent: true, … })`
**Fix:** Disable external entities and reject DOCTYPEs → [M-004](#m-004)
**Classification:** Insecure File Handling · [CWE-611](https://cwe.mitre.org/data/definitions/611.html) · [OWASP A04:2021](https://owasp.org/Top10/A04_2021/)

<a id="t-007"></a><a id="f-007"></a>
#### F-007 · Public Directory Listing

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `server.ts:280`
**Issue:** `/ftp`, `/support/logs` and `/encryptionkeys` are browsable without auth → order PDFs with PII, application logs and RSA/premium keys are all exposed.
**Root cause:** Sensitive directories are served without an authentication gate.
**Evidence:** ◌ ambiguous — the directories are mounted with index browsing enabled and no auth middleware in front.
`app.use('/support/logs', serveIndex('logs', { icons: true }))`
**Fix:** Require authentication on the sensitive directories → [M-006](#m-006)
**Classification:** Unauthenticated Management Plane · [CWE-548](https://cwe.mitre.org/data/definitions/548.html) · [OWASP A01:2021](https://owasp.org/Top10/A01_2021/)

<a id="t-008"></a><a id="f-008"></a>
#### F-008 · Path Traversal (ZIP)

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/fileUpload.ts:45`
**Issue:** ZIP extraction guards paths with a bypassable `includes()` check → `../../` entries overwrite files anywhere in the application directory.
**Root cause:** Archive paths are trusted without canonicalisation against a base directory.
**Evidence:** ✓ verified — the extracted path is checked with `includes()` rather than canonicalised against a base dir.
`if (absolutePath.includes(path.resolve('.'))) entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))`
**Fix:** Canonicalise paths and reject traversal outside the base dir → [M-004](#m-004)
**Classification:** Insecure File Handling · [CWE-22](https://cwe.mitre.org/data/definitions/22.html) · [OWASP A04:2021](https://owasp.org/Top10/A04_2021/)

<a id="t-012"></a><a id="f-012"></a>
#### F-012 · Uncontrolled Recursion (ReDoS)

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `lib/insecurity.ts:65`
**Issue:** `sanitizeSecure()` re-invokes itself until the input stabilises → crafted alternating input causes infinite recursion and stack-overflow DoS.
**Root cause:** A sanitiser recurses on its own output with no termination bound.
**Evidence:** ✓ verified — the function calls itself on its own output with no depth bound.
`if (sanitized !== input) return sanitizeSecure(sanitized)`
**Fix:** Bound the recursion / iterate instead of self-recursing → _not yet mapped ([§9](#9-mitigation-register))_
**Classification:** Denial of Service · [CWE-400](https://cwe.mitre.org/data/definitions/400.html) · [OWASP A04:2021](https://owasp.org/Top10/A04_2021/)

<a id="t-013"></a><a id="f-013"></a>
#### F-013 · NoSQL DoS (`$where` sleep)

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/showProductReviews.ts:38`
**Issue:** MarsDB `$where` runs user input and exposes a global `sleep()`; injecting `;global.sleep(2000)` blocks the Node.js event loop per request.
**Root cause:** User input reaches a `$where` expression evaluated by the datastore.
**Evidence:** ✓ verified — the review filter passes a user-controlled string into a `$where` expression.
`{ $where: 'this.id == ' + req.body.id }`
**Fix:** Reject `$where` and validate the query operator server-side → _not yet mapped ([§9](#9-mitigation-register))_
**Classification:** Denial of Service · [CWE-400](https://cwe.mitre.org/data/definitions/400.html) · [OWASP A04:2021](https://owasp.org/Top10/A04_2021/)

<a id="t-016"></a><a id="f-016"></a>
#### F-016 · JWT in localStorage

**Severity:** 🟠 High  ·  **Component:** [C-02](#c-02) Angular SPA Frontend  ·  **Location:** `request.interceptor.ts:13`
**Issue:** The JWT is stored in `localStorage`, readable by any injected script → XSS hijacks the session for the full 6-hour token lifetime with no server-side revocation.
**Root cause:** The session token is kept in script-readable storage, not an httpOnly cookie.
**Evidence:** ✓ verified — the token is written to and read from `localStorage` in the request interceptor.
`localStorage.setItem('token', authentication.token)`
**Fix:** Keep the session token in an httpOnly cookie → [M-011](#m-011)
**Classification:** Insecure Client-Side Storage · [CWE-922](https://cwe.mitre.org/data/definitions/922.html) · [OWASP A02:2021](https://owasp.org/Top10/A02_2021/)

<a id="t-021"></a><a id="f-021"></a>
#### F-021 · Mass-Assignment Access Control

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/updateProductReviews.ts:14`
**Issue:** `updateProductReviews` uses `{multi:true}` with an attacker-controlled `_id`; sending an empty `{}` updates every product review at once.
**Root cause:** A write runs without an object-level ownership / authorization check.
**Evidence:** ✓ verified — the update runs with `multi:true` and an unvalidated filter from the request body.
`reviews.update({ _id: req.body.id }, { … }, { multi: true })`
**Fix:** Enforce server-side object-ownership checks → [M-009](#m-009)
**Classification:** Broken Access Control · [CWE-284](https://cwe.mitre.org/data/definitions/284.html) · [OWASP A01:2021](https://owasp.org/Top10/A01_2021/)

<a id="t-022"></a><a id="f-022"></a>
#### F-022 · User-Table Disclosure

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `server.ts:362`
**Issue:** The auto-generated `/api/Users` endpoint returns all user records — password hashes, TOTP secrets and roles — to any authenticated caller.
**Root cause:** An auto-generated API exposes a model with no field filtering or row scoping.
**Evidence:** ✓ verified — the model is exposed through an auto-REST handler with no field filtering or row scoping.
`finale.resource({ model: UserModel, endpoints: ['/Users', '/Users/:id'] })`
**Fix:** Restrict the auto-generated Users API to admins and strip secrets → _not yet mapped ([§9](#9-mitigation-register))_
**Classification:** Error Information Disclosure · [CWE-200](https://cwe.mitre.org/data/definitions/200.html) · [OWASP A05:2021](https://owasp.org/Top10/A05_2021/)

<a id="t-025"></a><a id="f-025"></a>
#### F-025 · YAML Deserialization

**Severity:** 🟠 High _(raw Critical)_  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `server.ts:43`
**Issue:** js-yaml v3 `yaml.load()` executes JS via `!!js/function` tags and the app loads YAML uploads / `swagger.yml` without `safeLoad` → potential code execution.
**Root cause:** Untrusted serialized data is deserialized by a loader that can instantiate code.
**Evidence:** ◌ ambiguous — the unsafe `load()` is used on file content, but reachability from an untrusted upload is not fully confirmed.
`const doc = yaml.load(fs.readFileSync(file, 'utf8'))`
**Fix:** Use `yaml.safeLoad` / a schema-restricted loader → _not yet mapped ([§9](#9-mitigation-register))_
**Classification:** Code Execution via Unsafe Deserialization · [CWE-502](https://cwe.mitre.org/data/definitions/502.html) · [OWASP A08:2021](https://owasp.org/Top10/A08_2021/)

<a id="t-026"></a><a id="f-026"></a>
#### F-026 · XXE DoS (billion laughs)

**Severity:** 🟠 High  ·  **Component:** [C-03](#c-03) Data Layer  ·  **Location:** `routes/fileUpload.ts:82`
**Issue:** With `noent:true` in libxmljs2, a billion-laughs document expands entities exponentially → server memory and CPU exhaustion.
**Root cause:** The XML parser expands entities on untrusted documents with no limit.
**Evidence:** ✓ verified — entity expansion is enabled on the same parser that accepts uploaded XML.
`libxml.parseXml(data, { noent: true, … })`
**Fix:** Disable external entities and reject DOCTYPEs → [M-004](#m-004)
**Classification:** Injection · [CWE-776](https://cwe.mitre.org/data/definitions/776.html) · [OWASP A03:2021](https://owasp.org/Top10/A03_2021/)

<a id="t-006"></a><a id="f-006"></a>
#### F-006 · Server-Side Request Forgery (SSRF)

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/profileImageUrlUpload.ts:26`
**Issue:** Profile-image upload `fetch()`es a user-supplied URL with no allow-list → reaches cloud metadata endpoints, internal services and enables port scanning.
**Root cause:** An outbound request target is taken from user input with no allow-list.
**Evidence:** ✓ verified — the outbound request target is taken straight from request input.
`const response = await fetch(url)`
**Fix:** Allow-list the URL scheme + host before fetching → [M-005](#m-005)
**Classification:** Server-Side Request Forgery · [CWE-918](https://cwe.mitre.org/data/definitions/918.html) · [OWASP A10:2021](https://owasp.org/Top10/A10_2021/)

<a id="t-009"></a><a id="f-009"></a>
#### F-009 · Code Injection (B2B safeEval)

**Severity:** 🟠 High _(raw Critical)_  ·  **Component:** [C-05](#c-05) B2B Order API  ·  **Location:** `routes/b2bOrder.ts:19`
**Issue:** The B2B endpoint passes attacker-controlled `orderLinesData` to `safeEval`; the `notevil` library is not a real sandbox → prototype-pollution / escape sequences achieve RCE.
**Root cause:** Untrusted input is evaluated inside a non-isolating sandbox.
**Evidence:** ✓ verified — request body data is evaluated inside a non-isolating sandbox.
`const sandbox = { safeEval, orderLinesData }; safeEval(orderLinesData)`
**Fix:** Replace eval with structured JSON-schema validation → [M-003](#m-003)
**Classification:** Code Execution via Unsafe Eval · [CWE-94](https://cwe.mitre.org/data/definitions/94.html) · [OWASP A08:2021](https://owasp.org/Top10/A08_2021/)

<a id="t-014"></a><a id="f-014"></a>
#### F-014 · Insecure Direct Object Reference (IDOR)

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `routes/dataExport.ts:23`
**Issue:** Data export trusts `req.body.UserId` with no ownership check → any authenticated user exports another user's memories and data.
**Root cause:** An object is selected by a request-supplied id with no ownership check.
**Evidence:** ◌ ambiguous — the export is keyed on a request-supplied user id without a matching ownership assertion.
`const userId = req.body.UserId   // used directly to scope the export`
**Fix:** Tie every object lookup to the requesting user → [M-009](#m-009)
**Classification:** Broken Access Control · [CWE-639](https://cwe.mitre.org/data/definitions/639.html) · [OWASP A01:2021](https://owasp.org/Top10/A01_2021/)

<a id="t-024"></a><a id="f-024"></a>
#### F-024 · FTP Authorization Bypass

**Severity:** 🟠 High  ·  **Component:** [C-03](#c-03) Data Layer  ·  **Location:** `routes/order.ts:47`
**Issue:** Order PDFs are written to the publicly-listed `/ftp` directory → every customer's order, including PII, is downloadable by anyone.
**Root cause:** Generated artifacts are written to a publicly served directory.
**Evidence:** ✓ verified — the generated PDF is streamed into the public `ftp/` path.
`doc.pipe(fs.createWriteStream(path.join('ftp/', pdfFile)))`
**Fix:** Require authentication on the sensitive directories → [M-006](#m-006)
**Classification:** Broken Access Control · [CWE-285](https://cwe.mitre.org/data/definitions/285.html) · [OWASP A01:2021](https://owasp.org/Top10/A01_2021/)

<a id="t-010"></a><a id="f-010"></a>
#### F-010 · Open Redirect

**Severity:** 🟠 High  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `lib/insecurity.ts:137`
**Issue:** The redirect allow-list uses `url.includes()` → embedding an allow-listed string as a query parameter on an attacker URL passes the check.
**Root cause:** The redirect allow-list matches by substring, not by parsed origin.
**Evidence:** ✓ verified — the allow-list test is a substring `includes()` rather than an origin match.
`allowed = allowed || url.includes(allowedUrl)`
**Fix:** Match with `startsWith` against a parsed origin → [M-007](#m-007)
**Classification:** Open Redirect · [CWE-601](https://cwe.mitre.org/data/definitions/601.html) · [OWASP A01:2021](https://owasp.org/Top10/A01_2021/)

<a id="t-017"></a><a id="f-017"></a>
#### F-017 · Stored XSS (admin panel)

**Severity:** 🟠 High  ·  **Component:** [C-02](#c-02) Angular SPA Frontend  ·  **Location:** `administration.component.ts:60`
**Issue:** The admin component renders user emails via `bypassSecurityTrustHtml` → a stored payload in an email runs as persistent XSS in admin context.
**Root cause:** Untrusted data is marked trusted-HTML instead of being output-encoded.
**Evidence:** ✓ verified — user-controlled email is wrapped in `bypassSecurityTrustHtml` before rendering.
``user.email = this.sanitizer.bypassSecurityTrustHtml(`…${user.email}…`)``
**Fix:** Output-encode at the sink; drop `bypassSecurityTrustHtml` → [M-012](#m-012)
**Classification:** Cross-Site Scripting · [CWE-79](https://cwe.mitre.org/data/definitions/79.html) · [OWASP A03:2021](https://owasp.org/Top10/A03_2021/)

<a id="t-020"></a><a id="f-020"></a>
#### F-020 · DOM XSS (last-login IP)

**Severity:** 🟠 High  ·  **Component:** [C-02](#c-02) Angular SPA Frontend  ·  **Location:** `last-login-ip.component.html:10`
**Issue:** The last-login IP is bound via `[innerHTML]` with no sanitization; combined with `X-Forwarded-For` spoofing an attacker injects HTML/script.
**Root cause:** Untrusted data is bound to `innerHTML` instead of being output-encoded.
**Evidence:** ✓ verified — a server-influenced value is bound straight into `[innerHTML]`.
`<dd [innerHTML]="lastLoginIp"></dd>`
**Fix:** Drop unsafe binding; output-encode at the sink → [M-012](#m-012)
**Classification:** Cross-Site Scripting · [CWE-79](https://cwe.mitre.org/data/definitions/79.html) · [OWASP A03:2021](https://owasp.org/Top10/A03_2021/)

### 🟡 Medium (3)

<a id="t-011"></a><a id="f-011"></a>
#### F-011 · Insufficient Security Logging

**Severity:** 🟡 Medium  ·  **Component:** [C-01](#c-01) Express Backend API  ·  **Location:** `server.ts:350`
**Issue:** Only `morgan` HTTP logging is present — no security-event logging for auth failures, injection attempts or privilege escalation → attackers recon undetected.
**Root cause:** No security-event logging is wired into the auth / injection / authz paths.
**Evidence:** ◌ ambiguous — only a generic HTTP access logger is registered; no security-event hooks are present.
`app.use(morgan('combined'))`
**Fix:** Log security events (auth, injection, privilege escalation) → [M-008](#m-008)
**Classification:** Missing Audit Logging · [CWE-778](https://cwe.mitre.org/data/definitions/778.html) · [OWASP A09:2021](https://owasp.org/Top10/A09_2021/)

<a id="t-018"></a><a id="f-018"></a>
#### F-018 · Client-Side Info Disclosure

**Severity:** 🟡 Medium  ·  **Component:** [C-02](#c-02) Angular SPA Frontend  ·  **Location:** `score-board.component.ts:86`
**Issue:** The score board loads all challenge metadata (names, hints, solution flags) client-side → full challenge enumeration without completion.
**Root cause:** The server hands the full challenge dataset to the client unfiltered.
**Evidence:** ✓ verified — the full challenge list, including hints, is fetched to the client unfiltered.
`this.challenges = await this.challengeService.find()`
**Fix:** Serve only earned challenge metadata from the server → _not yet mapped ([§9](#9-mitigation-register))_
**Classification:** Error Information Disclosure · [CWE-200](https://cwe.mitre.org/data/definitions/200.html) · [OWASP A05:2021](https://owasp.org/Top10/A05_2021/)

<a id="t-019"></a><a id="f-019"></a>
#### F-019 · Client-Side Route-Guard Bypass

**Severity:** 🟡 Medium  ·  **Component:** [C-02](#c-02) Angular SPA Frontend  ·  **Location:** `app.guard.ts:18`
**Issue:** Angular route guards only check a `localStorage` token → a forged JWT navigates straight to admin routes, bypassing the UI-only guard.
**Root cause:** Authorization is enforced only in the client, not on the server.
**Evidence:** ✓ verified — the guard returns `true` purely on token presence in `localStorage`.
`return !!localStorage.getItem('token')`
**Fix:** Enforce the guard server-side, not just in the SPA → _not yet mapped ([§9](#9-mitigation-register))_
**Classification:** Broken Access Control · [CWE-602](https://cwe.mitre.org/data/definitions/602.html) · [OWASP A01:2021](https://owasp.org/Top10/A01_2021/)

---

## If you want to build it (pointers, no changes here)

- New renderer `_render_threat_register_cards` + template `threat-register-cards.md.j2`,
  selected by a contract flag (e.g. `threat_register_layout: cards | table`) so the table
  stays available for tooling and quick depth.
- Field sources (all already in the data): `Severity` = `threats[].risk`; `Component/Location`
  = `component` + `evidence.file:line`; `Issue` = scenario/issue; **`Root cause` = the
  finding's attack-class `description` from `data/attack-class-taxonomy.yaml`** (shared by class,
  i.e. real root-cause grouping); `Evidence` = `evidence` sentence + snippet (status from
  `evidence_check`); `Fix` = primary `M-NNN` short title; `Classification` = category + `cwe`
  (link `cwe.mitre.org/data/definitions/<n>.html`) + OWASP (link `owasp.org/Top10/A0X_2021/`).
- ToC note: 26 `####` headings add a per-finding index under §8 (handy, mirrors §9); emit a bold
  line instead if that's unwanted.
- QA: existing §8 link/anchor invariants apply; add a card-structure check (the six fields
  present, in order; CWE/OWASP links resolvable) mirroring the §9 checks.
