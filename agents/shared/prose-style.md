# Report prose — style anchor

This file is loaded by every agent that authors prose for the rendered
threat model (verdict, architecture-assessment, STRIDE scenarios,
remediation steps, security-architecture domain text, attack-walkthrough
intros). Read it once at the start of any prose-authoring step.

The reader is a software engineer, architect, or security reviewer.
Technical, time-pressed, allergic to filler. Write the way you would
write to a colleague reviewing a PR — not the way an LLM writes a
report. The five rules below are derived from concrete defects observed
in real generated reports; the examples are taken from those reports.

---

## Rule 1 — Specificity over generality, attacker as the subject

Name the file, line, library version, config key, API call, or HTTP
method+route. Generic phrases ("an attacker could", "in the codebase",
"various endpoints") are not findings — they are placeholders.

Specificity does not mean writing the *code's* behaviour as the subject
of every sentence ("`req.body.email` flows into…", "the payload
short-circuits…") — that reads as a passive code-review note, not
something a reader can act out step by step. The attacker's action is
the subject; the code mechanism is the reason the action works, not the
main clause. This governs `scenario` fields and §3 Attack Walkthrough
steps directly (juice-shop 2026-07-03 user report: Attack Steps must be
"aus der Sicht des Angreifers" — from the attacker's point of view,
clear and traceable).

**Avoid (vague — no file/line/payload):**
> An attacker could exploit the application to gain administrative access
> by submitting crafted input to the login endpoint.

**Avoid (specific, but the code is the subject — not attacker-actionable):**
> `req.body.email` flows unescaped into `models.sequelize.query()` at
> `routes/login.ts:34`. The payload `' OR '1'='1` short-circuits the
> WHERE clause and returns the first user row, which is the seeded
> admin account.

**Prefer (specific AND the attacker is the subject):**
> An attacker submits `' OR '1'='1` as the login form's email field.
> Because `req.body.email` flows unescaped into `models.sequelize.query()`
> at `routes/login.ts:34`, the crafted value short-circuits the WHERE
> clause — the query returns the first user row, the seeded admin
> account, and the attacker is authenticated as admin without a password.

All three name the same fact. The first is rhetoric — no reader can
reproduce it. The second is reproducible but reads as a static code
observation. The third is reproducible AND narratable: a reader can act
it out one step at a time, in order, as the attacker.

**Cap on `scenario` / Attack Steps (juice-shop 2026-07-03 user report — steps
had "far too much unnecessary detail"):** write **3–4 steps, one sentence each**.
Each sentence is a single attacker action as the main clause; the code
mechanism, if named, is a short subordinate "because…"/"since…" clause, not the
sentence. **At most one `file:line` per step.** Do not narrate the code's
internal control flow (which function calls what, which argument is missing,
which dependency version) — that belongs in the §6/§8 register row, not the
attack steps. If you cannot say the step as one action a reader could perform,
cut it.

**Avoid (code-flow narration, over-detailed — one "step" carrying four facts):**
> `verify()` at `lib/insecurity.ts:55` calls `jws.verify(token, publicKey)`
> without a third argument or an `algorithms:` allowlist, so the algorithm named
> in the attacker-supplied JWT header is trusted implicitly rather than pinned
> server-side to RS256; `isAuthorized()` (line 52) has the same gap.

**Prefer (attacker actions, one per step):**
> 1. Download the RSA public key served at `/encryptionkeys`.
> 2. Forge a JWT with `alg:HS256`, signing it with that public key as the HMAC
>    secret and setting `role: admin` — the server pins no algorithm, so it
>    accepts the forgery.
> 3. Call any admin-only endpoint with the forged token to act as admin.

---

## Rule 2 — Falsifiability over rhetoric

State the mechanism and what the system returns. Do not editorialise
about severity through metaphor or comparison.

**Avoid:**
- "trivial for a junior pentester"
- "the cryptographic trust model collapses"
- "any attacker can wreak havoc on the database"
- "this finding is catastrophic"

**Prefer:**
- "Exploitation requires only a public repo clone and a call to
  `jwt.sign(payload, privateKey, {algorithm: 'RS256'})`."
- "Once the private key is read from `lib/insecurity.ts:23`, any signer
  can mint a token the server accepts as `role=admin`."

A reader who disagrees with the rhetoric cannot test the rhetoric. A
reader who disagrees with the mechanism can test the mechanism.

---

## Rule 3 — Information-density over volume

Every sentence adds a fact the heading, table, or diagram does not
already convey. Section openers that restate the heading get cut.

**Avoid:**
> ### 6. Security Architecture
>
> This section consolidates the architectural narrative with the
> canonical control catalog. Each domain contains an assessment of how
> well the control is implemented and references to the concrete
> findings that exploit its gaps.

**Prefer:**
> ### 6. Security Architecture
>
> Catalog totals: ✅ 0 Adequate · ⚠️ 3 Partial · 🔶 5 Weak · ❌ 5 Missing
> · 13 controls tracked.

The "what does this section contain" job is done by the heading. Use
the opening line for a fact: a count, a constraint, an exception.

---

## Rule 4 — Scannable structure

One main clause per sentence. Enumerations of three or more items
become bullet lists or separate sentences, not comma chains.
Em-dashes only for tight apposition (a parenthetical aside) — never as
a glue replacing the period or the comma.

**Avoid:**
> NOT PRODUCTION-READY — exposes 14 Critical and 5 High findings across
> 3 components, including unauthenticated SQL injection granting admin
> access, a publicly committed RSA private key enabling offline JWT
> forgery, server-side code execution via eval(), and missing
> authorization on product modification endpoints.

**Prefer:**
> NOT PRODUCTION-READY — 14 Critical, 5 High across three components.
> The dominant attack paths:
>
> - Unauthenticated SQL injection on the login endpoint grants admin
>   access.
> - The RSA signing key is committed to the public repository, allowing
>   offline JWT forgery for any user.
> - `eval()` runs against user-supplied input on the profile route.
> - `PUT /api/Products` has no authentication middleware.

Same information, half the cognitive cost.

---

## Rule 5 — No boilerplate, no decorative repetition

Identical filler text repeated across rows or sections is a renderer
problem to solve renderer-side, not a prompt to normalise. When the
same explanation would apply to every row, write it once at the section
level and let the rows carry only their per-row specifics.

**Avoid (repeated in every row of an 8-row table):**
> | … | … | … | See §6 for the domain-level structural gaps. | Broad
>   defence-in-depth; no single finding directly addressed. |

**Prefer:**
> *(suppress the column entirely — the §6 cross-reference belongs in
> the section intro, not in 8 identical cells)*

Likewise: do not write "this section will discuss…" sentences, do not
re-introduce the same caveat in every paragraph, do not repeat the
finding's title inside its own scenario field.

---

## Rule 6 — Code identifiers in monospace

Any token that names a code symbol, a file or path, or a configuration
key MUST be wrapped in single backticks when it appears in prose. The
distinction is between **referring to code** (backticks required) and
**describing a concept** (plain prose). The reader scans backticks as
visual anchors that point at the source tree; un-backticked code tokens
read as part of the narrative and slow comprehension.

**Backtick required:**

- Function or method calls including their parentheses: `eval()`,
  `bypassSecurityTrustHtml()`, `vm.runInContext(safeEval())`,
  `models.sequelize.query()`.
- Dotted property accesses or namespaced identifiers: `req.body.email`,
  `process.env.SECRET_KEY`, `Object.assign`, `lib.insecurity.signToken`.
- Source-tree paths: `routes/login.ts`, `routes/login.ts:34`,
  `lib/insecurity.ts`, `frontend/src/app/about/about.component.ts`,
  `package.json`.
- Library, package, or middleware identifiers when treated as software
  artefacts: `express-jwt`, `libxmljs2`, `sanitize-html@1.4.2`.
- Configuration keys, flags, or HTTP headers when referenced as
  identifiers: `noent: true`, `SameSite=Strict`, `Authorization`,
  `Content-Security-Policy`.
- Regex or glob patterns when shown as code: `^F-\d{3}$`, `routes/**`.

**Plain prose (no backticks):**

- Vendor- or product-neutral concept nouns: "the login route", "the
  authentication middleware", "the sanitiser library", "SQL injection".
- The natural-language description of what code *does* — distinct from
  naming the code itself. "the function evaluates the user-supplied
  template" needs no backticks; the actual function name does.
- Section headings — code formatting in headings interacts badly with
  the GitHub anchor slug algorithm and breaks right-side TOC links.
  Refer to components by their display name in headings; never wrap
  component-ids or file paths in backticks inside `##` / `###` / `####`
  lines.

**Avoid (typical drift):**

> Two routes pass attacker-controlled strings directly to JavaScript
> evaluation functions — eval() in the profile handler and
> vm.runInContext(safeEval()) in the B2B order handler — providing
> two independent paths to arbitrary server-side code execution.

**Prefer:**

> Two routes pass attacker-controlled strings directly to JavaScript
> evaluation functions — `eval()` in the profile handler and
> `vm.runInContext(safeEval())` in the B2B order handler — providing
> two independent paths to arbitrary server-side code execution.

The QA gate `check_inline_code_format` enforces this by flagging
unbacked path-shaped tokens (e.g. `routes/login.ts`, `lib/insecurity.ts`)
in narrative paragraphs. Less-mechanical violations (function calls in
prose) are reviewer-flagged, not gate-flagged — the rule is for the
author, the gate catches the highest-cost misses.

---

## Rule 7 — Lead with the concrete thing; cut the textbook purpose

This rule governs the *opening* of any descriptive paragraph — most visibly the §6 control intros, but the same defect appears in scenario and remediation prose. Two AI tells dominate:

**Formulaic subject stem.** `The application <verb>s …`, `The system …`, `The server …`, `The framework …`. One such opener in a section is fine; a column of them down a section is the signature of a model filling a template. A domain expert names the artifact first.

**Avoid (every intro starts the same way):**
> The application authenticates users by comparing a submitted password hash …
> The application offers an optional second factor …
> The application uses Sequelize as an ORM layer …

**Prefer (lead with the route, file, library, component):**
> `routes/login.ts` checks a submitted password hash against the `Users` table …
> TOTP is available as an opt-in second factor via `routes/2fa.ts` …
> Sequelize backs most queries; the login and search routes call raw `models.sequelize.query()` …

**Textbook-purpose padding.** Trailing clauses that explain why the control category exists in the abstract — `with the intention that …`, `with the expectation that …`, `is expected to …`, `preventing X from being interpreted as Y`, `so that a breach does not directly yield credentials`. The reader knows what parameterized queries and output encoding are for. These clauses add zero facts about THIS app and are the biggest single source of paragraph sprawl.

**Avoid:**
> The application stores a hashed form of each password so that a database breach does not directly yield usable credentials, with the hashing algorithm providing a work factor that slows offline recovery attempts.

**Prefer:**
> Passwords are hashed before storage in the `Users` table. The algorithm is unsalted MD5 (`lib/insecurity.ts:43`) — a single fast hash, no work factor.

State what the code does, then stop. The gap goes in the assessment, not in a purpose clause.

**Multi-issue blocks become bullets.** When an assessment covers two or more discrete weaknesses, a short framing sentence plus one bullet per weakness scans far faster than the same facts welded into a 60-word paragraph. Keep flowing prose only when the weaknesses form one causal chain.

**Avoid (two unrelated weaknesses fused):**
> The login query at `routes/login.ts:34` interpolates `req.body.email` into raw SQL, and separately `lib/insecurity.ts:43` hashes passwords with unsalted MD5, so any dump obtained through injection immediately yields recoverable credentials.

**Prefer:**
> Two independent weaknesses sit on the login path:
>
> - `routes/login.ts:34` interpolates `req.body.email` into raw SQL — `' OR 1=1--` returns the seeded admin row.
> - `lib/insecurity.ts:43` hashes passwords with unsalted MD5, so a dump yields plaintext directly.

---

## What gets rejected

QA review treats these as content defects, not stylistic preferences:

- Generic phrases without file:line evidence (Rule 1)
- Severity stated through metaphor instead of mechanism (Rule 2)
- Section openers that restate the heading (Rule 3)
- Sentences with 3+ comma-separated clauses where a list would do (Rule 4)
- Repeated boilerplate across rows or paragraphs (Rule 5)
- Formulaic `The application <verb>s …` openers repeated down a section, or textbook-purpose padding clauses (Rule 7)

A measure that shortens prose without preserving information is **not**
an improvement. Optimise for the engineer's time-to-understand, not for
token count. If trimming a sentence removes a fact, keep the sentence.

---

## Control narrative quality bar (§6 Security Architecture)

Section 7 narratives must satisfy the rules below. For current
`security_schema=v2`, §6 is a 13-section control-category model with
section-level `Verdict / Controls covered / Implemented controls /
Assessment` labels and H4 subcontrols carrying `Security assessment` plus
`Relevant findings`. The Architect-Reviewer and QA gates check this shape via
`contract`, `control_subsection_coverage`, and `architectural_prose`.

The shared root cause behind these rules: pre-2026-05 §6 narratives drifted
into pure finding-lists ("the application has SQL injection at routes/
login.ts:34, an XSS bypass at about.component.ts:12, …"). A reader needs
to know **what** the control class is and **how** this codebase implements
it BEFORE they can evaluate the findings. Otherwise the section reads like
an unstructured AI-generated dump of greps and misses the architecture-
level signal entirely.

> **§6.X authoring shape.** The body shape is defined in
> `agents/appsec-threat-renderer.md → "§6.X authoring pattern"`:
> H3 control-category section → `**Verdict:**` → `**Controls covered:**`
> links → `**Implemented controls:**` → `**Assessment:**` → H4 subcontrol
> blocks with `**Security assessment**` and `**Relevant findings**`.
> Structural requirements are enforced by
> `qa_checks.py check_control_subsection_coverage`.

| # | Rule | Heuristic check |
|---|---|---|
| §6-1 | **Control context before gap detail.** Every H4 control block opens with a positive intro paragraph that explains what the control is and how this codebase implements it before naming weaknesses. | Intro paragraph appears before `**Security assessment**`; it does not open with `No`, `Missing`, `Not implemented`, or `There is no`. |
| §6-2 | **Concrete implementation evidence.** Implementation claims cite a verifiable artifact: file path, route, library, IaC resource, platform API, or generated evidence excerpt. | At least one artifact token from recon/YAML/evidence appears in the block. |
| §6-3 | **Findings live under the affected control.** Finding bullets appear in the relevant H4 block, not as a detached domain-level dump. | `**Relevant findings**` is a standalone label followed by bullets; finding-to-section routing follows `schema_v2.finding_routing`. |
| §6-4 | **Dense issue lists become bullets.** Two or more discrete weaknesses in one assessment block use bullets instead of one long paragraph. | Paragraphs with 3+ finding/mitigation refs are flagged for bullet formatting. |
| §6-5 | **No AI-typical filler.** Avoid `leverages`, `robust`, `comprehensive`, `ensures`, `facilitates`, `in essence`, `seamless`, `cutting-edge`, `state-of-the-art`, and renderer-specific banned vocabulary such as `mechanism layer` or `codified rule`. | Enforced by `qa_checks.py check_architectural_prose`. |

**How to apply across architectures.** None of the §6 rules assume a
specific application class. They work as written for:

- **User-facing web** (Express + React/Angular/Vue, Django, Rails, Spring): file paths and library tokens are abundant; QB-3 trivially satisfied.
- **Serverless** (AWS Lambda, GCP Cloud Functions, Azure Functions): artifacts are IaC resources (`serverless.yml`, Terraform, SAM template), function ARNs, IAM role names. QB-3 admits these as verifiable artifacts.
- **Service mesh** (Istio, Linkerd, Consul Connect): artifacts are mesh resources (`PeerAuthentication`, `RequestAuthentication`, `AuthorizationPolicy`, SPIFFE IDs). QB-3 admits these too.
- **Mobile** (iOS, Android): artifacts are platform APIs (`URLSession`, `Keychain`, `BiometricPrompt`), entitlement keys, and Info.plist / AndroidManifest entries.
- **Embedded / firmware:** artifacts are linker-section names, hardware register references, and bootloader stages.

The rules are about narrative *shape* (control context, implementation evidence, then gap), not about which technology vocabulary is in scope. The vocabulary is supplied per-app by the recon-summary; the validator never compares against a hardcoded library list.

---

## Rule 6 — Pluralise correctly; the `(s)` suffix is forbidden

When emitting a count of an inflected noun, branch on the count: "1 component" vs "5 components". Never use the slash form "1 component(s)" / "5 component(s)" — that is technical-docs filler dialect, not professional prose. Same rule for "item / items", "finding / findings", "control / controls".

**Avoid:**
> This threat model covers 5 component(s); 3 finding(s) trace to outdated dependencies.

**Prefer:**
> This threat model covers 5 components; 3 findings trace to outdated dependencies.

The pluralize helper in `scripts/compose_threat_model.py:pluralize()` exists for generator code; LLM-authored prose should branch inline.

---

## Where this file applies

Loaded explicitly by:

- `agents/appsec-stride-analyzer.md` — before authoring `scenario`,
  `mitigation_title`, `remediation.steps`, `controls_in_place`.
- `agents/phases/phase-group-finalization.md` — before authoring
  `ms-verdict.json` and `ms-architecture-assessment.json`, and before
  filling the §6 narrative placeholders.
- `agents/appsec-threat-renderer.md` — same set of fragments at Stage 2.
- `agents/shared/ms-template.md` — referenced as the authority for prose
  rules cited from the Management Summary template.

Drift from this anchor is guarded by `tests/test_agent_definitions.py`.

## Companion file

`agents/shared/prose-samples.md` carries the worked **Before/After
pairs** — concrete passages from real reports showing the AI-flavored
shape and the human-style rewrite, the banned-vocabulary list, the
voice statement, and a pre-write self-check. The two files are loaded
together: this file is the rules, that file is the examples. Sonnet
imitates examples more reliably than it follows rules — keep both
current.
