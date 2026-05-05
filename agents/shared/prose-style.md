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
