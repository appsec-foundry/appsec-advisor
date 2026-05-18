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

## Rule 1 — Specificity over generality

Name the file, line, library version, config key, API call, or HTTP
method+route. Generic phrases ("an attacker could", "in the codebase",
"various endpoints") are not findings — they are placeholders.

**Avoid:**
> An attacker could exploit the application to gain administrative access
> by submitting crafted input to the login endpoint.

**Prefer:**
> `req.body.email` flows unescaped into `models.sequelize.query()` at
> `routes/login.ts:34`. The payload `' OR '1'='1` short-circuits the
> WHERE clause and returns the first user row, which is the seeded
> admin account.

The second version is reproducible. The first is rhetoric.

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
> ### 7. Security Architecture
>
> This section consolidates the architectural narrative with the
> canonical control catalog. Each domain contains an assessment of how
> well the control is implemented and references to the concrete
> findings that exploit its gaps.

**Prefer:**
> ### 7. Security Architecture
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
> | … | … | … | See §7 for the domain-level structural gaps. | Broad
>   defence-in-depth; no single finding directly addressed. |

**Prefer:**
> *(suppress the column entirely — the §7 cross-reference belongs in
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

## What gets rejected

QA review treats these as content defects, not stylistic preferences:

- Generic phrases without file:line evidence (Rule 1)
- Severity stated through metaphor instead of mechanism (Rule 2)
- Section openers that restate the heading (Rule 3)
- Sentences with 3+ comma-separated clauses where a list would do (Rule 4)
- Repeated boilerplate across rows or paragraphs (Rule 5)

A measure that shortens prose without preserving information is **not**
an improvement. Optimise for the engineer's time-to-understand, not for
token count. If trimming a sentence removes a fact, keep the sentence.

---

## Control narrative quality bar (§7 Security Architecture)

Section 7 narratives — both per-domain (§7.3 IAM, §7.4 AuthZ, §7.5 InputVal,
…) and per-flow (§7.3.N) — additionally MUST satisfy the eight rules below.
The Architect-Reviewer checks each rule via a deterministic post-render
gate; violations either auto-repair (heading lint, label-existence) or
flag for re-render (concept-first, file:line ratio).

The shared root cause behind these rules: pre-2026-05 §7 narratives drifted
into pure finding-lists ("the application has SQL injection at routes/
login.ts:34, an XSS bypass at about.component.ts:12, …"). A reader needs
to know **what** the control class is and **how** this codebase implements
it BEFORE they can evaluate the findings. Otherwise the section reads like
an unstructured AI-generated dump of greps and misses the architecture-
level signal entirely.

| # | Rule | Heuristic check |
|---|---|---|
| QB-1 | **First sentence is concept-level.** No `file:line`, no CWE-NNN, no T-NNN/F-NNN reference in the opening sentence of any §7.X domain narrative or §7.3.N flow narrative. | Regex `(\w+\.[a-z]+:\d+\|CWE-\d+\|[TF]-\d{3,})` MUST NOT match the first sentence. |
| QB-2 | **Three bold-labelled blocks per domain narrative.** Every §7.X domain narrative carries exactly three bold-labelled paragraphs in order: `**What this control does.**`, `**How it is implemented here.**`, `**Where it falls short.**`. (When the domain is genuinely Not Applicable, substitute a single `_Not applicable — …_` italic line for all three blocks.) Flow narratives (§7.3.N) carry the first two labels; the third role is fused into the existing `**Risk assessment:**` trailer. | All three bold-label tokens present, in order, with intervening prose. |
| QB-3 | **Implementation block names a verifiable artifact.** The `**How it is implemented here.**` block MUST cite at least one artifact that the recon-summary actually contains: file path, package name, IaC resource ID (`aws_iam_role.<name>`), K8s manifest key (`spec.tls.termination`), mesh resource (`PeerAuthentication/<name>`), or framework token. **No hardcoded library list** — the validator pulls allowed artifact tokens from the per-app `.recon-summary.md`, so the rule generalises across web / serverless / mesh / mobile / embedded. | At least one artifact token from the recon snapshot appears in this block. |
| QB-4 | **Concept block file:line ratio ≤ 30 %.** In the `**What this control does.**` block, no more than 30 % of sentences may contain a `file:line` or other verifiable-artifact reference. The "How" block has no upper limit; the "What" block keeps the conceptual frame. | `count(sentences with artifact ref) / count(sentences) ≤ 0.30` per block. |
| QB-5 | **§7.3.N heading must contain a mechanism token.** Each `#### 7.3.N <X> Flow` heading must include at least one token from the IAM/SessionMgmt mechanism vocabulary in `data/architectural-controls.yaml`. The token list is derived dynamically from `controls[].name + aliases` filtered to `kind: mechanism`. Token-format-only headings (`JWT RS256 Signing Flow`, `Bearer Token Flow`) and primitive-only headings (`Password Hashing Flow`, `Rate Limiting Flow`, `Session Revocation Flow`) are forbidden. | `sections-contract.yaml → auth_method_decomposition.{method_whitelist, forbidden_heading_patterns}` |
| QB-6 | **First T-NNN/F-NNN reference appears AFTER the second bold label.** A `[T-NNN]` or `[F-NNN]` link in the `**What this control does.**` or `**How it is implemented here.**` blocks indicates the narrative skipped the conceptual frame and jumped straight to findings. | Position-of-first-`[T-NNN]` > position-of-`**Where it falls short.**`. |
| QB-7 | **No AI-typical floskeln in concept blocks.** The "What" and "How" blocks MUST NOT contain: `leverages`, `robust`, `comprehensive`, `ensures`, `facilitates`, `in essence`, `seamless`, `cutting-edge`, `state-of-the-art`. These are filler that a domain expert would never write. | Word-list scan; warnings flagged at QA gate, hard-fail when ≥3 in one block. |
| QB-8 | **No verbatim copy of a controls-table cell.** No sentence in the domain narrative may share a 6-or-more-word contiguous span with any cell of the same domain's controls table. The narrative interprets — the table presents the data. | n-gram match (n=6) between narrative sentences and table cells. |
| QB-9 | **Flow narrative intro precedes diagram.** Every `#### 7.3.N <X> Flow` sub-section must have at least one non-empty prose sentence between the heading and the first ` ```mermaid ` fence. The sentence names the flow's purpose and the key code path — it is not a restatement of the heading. A section that opens directly with ` ```mermaid ` gives readers no orientation before the timing diagram. | Enforced by `qa_checks.py check_auth_method_decomposition` via `contract: auth_method_decomposition.required_body_elements: intro_before_diagram`. |
| QB-10 | **sequenceDiagram Notes describe mechanism, not finding.** `Note over` annotations inside §7.3.N flow diagrams must describe what the system *does* at that step (the designed behavior). Finding references ([T-NNN], [F-NNN]) and vulnerability labels ("SQL injection vector", "auth bypass") belong in the `**Findings in this flow:**` bullet list below the diagram — not embedded in `Note over` labels. A reader must be able to understand the intended control flow from the diagram alone, before reading the findings list. | Warning-level heuristic: `qa_checks.py` flags `Note over` lines containing `T-\d{3}`, `F-\d{3}`, or tokens like "bypass", "injection", "vector" in §7.3 diagrams. |
| QB-11 | **Protocol-name headings need a standards-vs-custom qualifier.** When a `#### 7.3.N` heading uses a token that is also a standards protocol name (JWT, OAuth, SAML, OIDC, WebAuthn), the `**What this flow does.**` opening sentence must clarify whether this is a standards-based flow (RFC/spec reference) or a custom in-house implementation that reuses the token format. One sentence suffices: *"This is a custom JWT-based flow — not OAuth 2.0 or OIDC; the application mints and validates its own tokens without an authorization server."* | Guidance only — no gate check. Applied manually during Phase 11 authoring. |

**How to apply across architectures.** None of the eight rules assume a
specific application class. They work as written for:

- **User-facing web** (Express + React/Angular/Vue, Django, Rails, Spring): file paths and library tokens are abundant; QB-3 trivially satisfied.
- **Serverless** (AWS Lambda, GCP Cloud Functions, Azure Functions): artifacts are IaC resources (`serverless.yml`, Terraform, SAM template), function ARNs, IAM role names. QB-3 admits these as verifiable artifacts.
- **Service mesh** (Istio, Linkerd, Consul Connect): artifacts are mesh resources (`PeerAuthentication`, `RequestAuthentication`, `AuthorizationPolicy`, SPIFFE IDs). QB-3 admits these too.
- **Mobile** (iOS, Android): artifacts are platform APIs (`URLSession`, `Keychain`, `BiometricPrompt`), entitlement keys, and Info.plist / AndroidManifest entries.
- **Embedded / firmware:** artifacts are linker-section names, hardware register references, and bootloader stages.

The rules are about narrative *shape* (concept-then-implementation-then-gap), not about which technology vocabulary is in scope. The vocabulary is supplied per-app by the recon-summary; the validator never compares against a hardcoded library list.

---

## Where this file applies

Loaded explicitly by:

- `agents/appsec-stride-analyzer.md` — before authoring `scenario`,
  `mitigation_title`, `remediation.steps`, `controls_in_place`.
- `agents/phases/phase-group-finalization.md` — before authoring
  `ms-verdict.json` and `ms-architecture-assessment.json`, and before
  filling the §7 narrative placeholders.
- `agents/shared/ms-template.md` — referenced as the authority for prose
  rules cited from the Management Summary template.

Drift from this anchor is guarded by `tests/test_agent_definitions.py`.
