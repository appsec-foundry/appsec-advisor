# Report prose — worked Before/After pairs

> Companion to `prose-style.md`. That file states the rules; this file
> shows them applied to real prose. Each pair is a passage that was
> actually rendered into a threat-model report, the AI-flavored pattern
> it exhibited, the human-style rewrite, and the rule that follows.
>
> Loaded by the renderer and finalization agents before authoring
> `ms-verdict.json`, `ms-architecture-assessment.json`, **and the §6
> Security Architecture control narratives** (H4 intro paragraphs and
> `**Security assessment**` blocks) — Claude Sonnet imitates worked
> examples more reliably than it follows abstract rules. Pairs A–E
> target Management-Summary fields; Pairs F–G target §6 control prose.
>
> When a new AI-tell shows up in a real run, add it here as a pair —
> not as a new rule in `prose-style.md`. Rules without examples drift;
> examples don't.

---

## Pair A — MS Verdict Opening (`ms-verdict.json::verdict_prose`)

### BEFORE (95 words, 5 sentences, AI-flavored)

> 🔴 Not production-ready. This deliberately vulnerable training application embeds intentional weaknesses across every tier of its architecture. The application exposes multiple independent paths to full account and host compromise that require no elevated privilege or specialised tooling - a user with only a browser and repository read access can bypass authentication entirely. Closing the risk requires structural changes at the authentication, data-access, and secret-management layers, not a single-point patch.

### Diagnose
- "embedding intentional weaknesses across every tier of its architecture" — three nominalizations in one breath
- "exposes multiple independent paths to full account and host compromise" — nominal style; "compromise" as a noun
- "a user with only a browser and repository read access" — long noun phrase; a human writes "anyone"
- Closing sentence "Closing the risk requires structural changes at the X, Y, and Z layers, not a single-point patch" — typical AI cadence: triplet + "not a single X" antithesis

### AFTER (62 words, 4 sentences, human)

> 🔴 Not production-ready. The app is a training target — intentional weaknesses live in every tier. Anyone with a browser and repo read access can take over admin accounts and the host server through several independent paths, none of which need elevated privilege or special tooling. Fixing this means rebuilding authentication, data access, and secret management — not patching a single bug.

### Rule
1. **Dissolve nominalizations**: "embedding weaknesses" → "weaknesses live"
2. **Break the triplet cadence**: not "X, Y, and Z layers" — instead a verb form with an em-dash close
3. **"a user with only a browser…" → "anyone with…"**: shorter, more human
4. **Word-count reduction ~30 %** with no loss of content

---

## Pair B — MS Verdict Closing (`ms-verdict.json::closing_prose`)

### BEFORE (37 words, 1 sentence, AI-flavored)

> Nineteen mitigations are identified; replacing the hardcoded secrets with runtime-injected values, switching to parameterized database queries, and upgrading the password hashing algorithm address the highest-impact paths and are prerequisites for any production readiness evaluation.

### Diagnose
- "Nineteen mitigations are identified" — passive opener
- triple-parallel "replacing... switching... upgrading..." — symmetric triplet, classic AI
- "are prerequisites for any production readiness evaluation" — bureaucratic prose; nominalizes "prerequisite"

### AFTER (40 words, 3 sentences, human)

> Nineteen mitigations follow. Three matter most: move secrets out of source, switch raw SQL to parameterized queries, replace MD5 password hashes. Without those three, production readiness is not on the table.

### Rule
5. **Active over passive** in the opener
6. **Colon list instead of gerund triplet**: "X, Y, and Z" with `-ing` forms → "X. Y. Z." with imperative verbs
7. **Punchline close**: a concrete image ("not on the table") instead of a cliché ("are prerequisites for any production readiness evaluation")
8. **Shorter sentences**: 1 sentence → 3 sentences, same content, more readable

---

## Pair C — Crypto Weakness Description (`ms-architecture-assessment.json::weaknesses[0].description`)

### BEFORE (54 words, 2 sentences)

> A 1024-bit RSA private key, an HMAC secret, and a cookie-signing secret are all hardcoded as string literals in `lib/insecurity.ts`. These are repository-public values — anyone who clones the repo can sign arbitrary JWTs or forge session cookies without server access.

### Diagnose
Already pretty good — concrete, has the file path, punchline at the end. But:
- "are all hardcoded" — passive
- "These are repository-public values" — demonstrative-pronoun opener + copula sentence; a bit stiff

### AFTER (45 words, 2 sentences)

> Three secrets live as hardcoded string literals in `lib/insecurity.ts`: a 1024-bit RSA private key, an HMAC secret, and a cookie-signing secret. Cloning the repo gives you everything needed to sign JWTs or forge session cookies — no server access required.

### Rule
9. **Punchline opener with a count**: "Three secrets live as…" names the scandal immediately
10. **Colon instead of a list-in-the-subject**: the claim first, then the evidence
11. **"You" as the subject** when it reads naturally: "Cloning the repo gives you everything…" reads like a reviewer comment, not a compliance report. (Use sparingly, not as the default.)

---

## Pair D — Authorization Weakness Description (`ms-architecture-assessment.json::weaknesses[3].description`)

### BEFORE (53 words, 2 sentences)

> Several REST endpoints exposed via `finale-rest` accept mass-assignment updates to privileged model fields; the product update endpoint at `server.ts:361` has no authentication middleware; and Angular route guards enforce access control only in the browser without a server-side equivalent. Authorization is inconsistent across the API surface.

### Diagnose
- "Several" — vague; exactly how many?
- Three semicolon-separated clauses in one sentence — symmetric, formal
- Closing sentence "Authorization is inconsistent across the API surface" — generic AI closing cadence "X is Y across Z"

### AFTER (51 words, 4 sentences)

> `finale-rest` exposes REST endpoints that accept mass-assignment to privileged model fields. The product update at `server.ts:361` runs without auth middleware. Angular route guards run only in the browser; there is no server-side equivalent. Three different gaps, one missing piece: server-side authorization as a pattern.

### Rule
12. **Vary sentence length**: 4 sentences of lengths 11/7/13/13 — rhythm instead of symmetry
13. **Close with a diagnosis instead of a generalization**: not "X is inconsistent across Y" — instead "the missing pattern is X". Names the root cause.
14. **Drop "Several"**: either give the number or rebuild the clause so the number sits in the context

---

## Pair E — Operational Strengths Intro (out of Iteration 1 — reference for later)

### BEFORE (61 words, 2 sentences)

> Despite the structurally deficient design, the project carries a baseline of categorical strengths. The table below groups individual controls into broad-stroke clusters (full per-control breakdown in [Section 7](#6-security-architecture)). Only clusters that genuinely rate as a strength (Adequate or Partial) appear here - clusters demoted to Weak by open Critical/High findings in their defensive remit are excluded from this section and live in [§6](#6-security-architecture) instead.

### Diagnose
- "Despite the structurally deficient design" — formal contrastive opener
- "carries a baseline of categorical strengths" — "carries a baseline of" = bureaucratic prose
- "The table below groups individual controls into broad-stroke clusters" — meta-narration about the table (the reader can see the table)
- "broad-stroke clusters" — vague adjective-noun combo
- Closing sentence: 36 words, 3 nested clauses

### AFTER (44 words, 3 sentences)

> Not everything is broken. The clusters below list controls that actually work (Adequate or Partial). Anything weakened by an open Critical/High finding moved to [§6](#6-security-architecture) instead — appearing here would be misleading.

### Rule
15. **Drop meta-narration**: no "the table below shows…" — the table shows itself
16. **Drop formal contrastive opener**: "Despite the X, Y" → a short, direct sentence
17. **Drop empty adjective-noun-combos**: "broad-stroke clusters", "categorical strengths", "structurally deficient design"
18. **Reason at the end instead of a hierarchy explanation**: "appearing here would be misleading" says the why in 4 words

---

## Pair F — §6 H4 Control Intro (`security-architecture.md` H4 positive-case intro)

### BEFORE (40 words, 1 sentence, AI-flavored)

> The application uses Sequelize as an ORM layer to query SQLite, with the intention that user-supplied values are passed as bound parameters rather than concatenated into query strings, preventing query structure from being altered by attacker-controlled input.

### Diagnose
- Opener "The application uses …" — formulaic subject stem; 9 of 13 §6 intros in the same report start this way
- "with the intention that … rather than … " — the textbook purpose of the control class, not what THIS app does
- "preventing query structure from being altered by attacker-controlled input" — the same purpose again, paraphrased
- A single 40-word sentence; the concrete fact (which routes bypass the ORM) is missing entirely

### AFTER (32 words, 2 sentences, human)

> Sequelize backs most relational queries in this codebase. Two routes opt out and build SQL by hand — the password login (`routes/login.ts:34`) and product search (`routes/search.ts:23`) call raw `models.sequelize.query()`.

### Rule
19. **Concrete subject first**: "Sequelize backs most queries …" instead of "The application uses Sequelize …" — the domain expert names the artifact, not the generic actor
20. **Cut the purpose padding**: no "with the intention that … preventing …" — the reader knows what parameterized queries are for
21. **Deliver the actual fact**: WHICH routes deviate, with file:line — that is the information that belongs only in THIS report

---

## Pair G — §6 Security-Assessment Block (`security-architecture.md` `**Security assessment**`)

### BEFORE (1 dense paragraph, 2 welded-together weaknesses)

> The login query at `routes/login.ts:34` builds its SQL string by directly interpolating `req.body.email` and the pre-hashed password into a raw `models.sequelize.query()` call, bypassing Sequelize's parameter binding entirely. A `' OR 1=1--` payload in the email field short-circuits the WHERE clause and returns the first database row, which is the seeded admin account. Separately, `lib/insecurity.ts:43` hashes passwords with unsalted MD5, so any database dump obtained through injection immediately yields recoverable plaintext credentials for all accounts.

### Diagnose
- Two independent weaknesses (SQLi + MD5) in one 70-word block; "Separately, …" is the seam marker
- The reader has to parse the paragraph to spot two separate findings
- NOT causally chained — SQLi and MD5 are independent → they belong in separate bullets

### AFTER (framing sentence + 2 bullets)

> Two independent weaknesses sit on the login path:
>
> - `routes/login.ts:34` interpolates `req.body.email` into a raw `models.sequelize.query()` string. `' OR 1=1--` short-circuits the WHERE clause and returns the seeded admin row.
> - `lib/insecurity.ts:43` hashes passwords with unsalted MD5, so any dump from that injection yields plaintext for every account.

### Rule
22. **≥2 separate weaknesses → bullet list** with one framing sentence; one bullet per weakness
23. **Read "Separately, …" / "In addition, …" as a seam signal**: if it shows up, it was probably already a list
24. **Keep running prose only for a causal chain**: "key committed → forged token passes → route guard moot" reads better as a narrative; independent weaknesses do not

---

## Derived vocabulary

### Banned (in polisher output, because they are AI tells)

Adjectives: `robust`, `comprehensive`, `holistic`, `seamless`, `crucial`, `vital`, `key` (as a modifier), `categorical`, `broad-stroke`, `structurally deficient`

Verbs: `leverage`, `facilitate`, `ensure`, `enable`, `embed` (except in the sense of "embedded systems"), `carry a baseline of`

Quantifiers without a number: `several`, `multiple`, `various`, `numerous`, `many`

Transitions: `furthermore`, `moreover`, `additionally`, `in essence`, `in summary`, `notably`, `importantly`

Meta-clichés: `it is worth noting`, `it should be noted`, `it is important to note`, `the table below shows`, `as can be seen`

Generic closing cadences: `X is Y across the Z`, `X requires Y at the A, B, and C layers`, `X are prerequisites for any Y`

Formulaic opener stems (max. 1× per §6.X section): `The application <verb>s …`, `The system …`, `The server …`, `The framework …` — instead, begin with a route/file/library/component

Purpose-padding clauses (always cut): `with the intention that …`, `with the expectation that …`, `is expected to …`, `is intended to …`, `preventing X from being Y`, `so that <generic purpose>`

### Preferred Idioms (positive)

- **Em-dash for a punchline close**: `… — no server access required.`
- **Colon for lists within a sentence**: `Three matter most: X, Y, Z.`
- **Variable sentence length**: 3-15 words, mixed
- **Diagnosis close**: "the missing piece is X" / "the pattern that's absent is X"
- **Number instead of a quantifier**: "three", "four", "every", "all" — not "several", "multiple"
- **Active voice** for openers
- **Imperative verbs in mitigation lists**: "move", "switch", "replace" — not "moving", "switching", "replacing"

---

## Voice statement (apply when authoring any prose field)

> You are writing prose that a technical reviewer would put in a PR
> comment thread — not a compliance report, not a consulting deck, not
> marketing copy. The reader is a software engineer or security reviewer
> who is time-pressed and allergic to filler. Write the way you would
> explain what you found to the next engineer on call: punchline first,
> evidence in the next breath, one concrete diagnosis at the end. Short
> sentences are allowed and good. Symmetric triplets ("X, Y, and Z")
> sound machine-generated; break them with em-dashes or split into
> separate sentences. If a sentence could appear in any security report
> for any app, rewrite it until it can only appear in THIS report for
> THIS app.

---

## Pre-write self-check (run before saving any prose fragment)

Five questions to ask about each prose field you just wrote:

1. **Could this sentence appear in a report about a different app?**
   If yes: too generic — add concrete evidence (file path, function name, count, version).
2. **Does it use any banned-vocabulary word?** (see list above)
   If yes: rewrite using a concrete verb or noun.
3. **Is the punchline in the first 8 words?**
   If no: re-order so the main claim leads.
4. **Are all sentences in the same length-bracket (±2 words)?**
   If yes: AI-rhythm — break it with a short sentence or a colon.
5. **Does the final sentence diagnose something, or just summarize?**
   Summary endings ("X is Y across the Z") are AI tells — replace with
   a diagnosis ("the missing piece is X") or drop the sentence.

≥2 negative answers → rewrite the field before saving.

---

## Pair G — MS Verdict bullet ALTITUDE (`ms-verdict.json::bullets[].body`)

The Verdict is the one block the **product owner / project lead** reads. Bullets must state the *business consequence* and the *class* of weakness. The `refs` field is audit provenance only; engineers find the detail in §8/§6. Config-level detail (config keys, library versions, CVE numbers, file:line, framework symbols, ports) belongs there, never here.

### BEFORE (engineer altitude — wrong for the Verdict)

> - **Unauthenticated access to all endpoints** — `package.json` lists only `express`, `lodash`, and `sequelize` — no `jsonwebtoken`, `passport`, or session library. Every route on port 3000 is reachable without credentials.
> - **Prototype pollution enables authorization bypass** — `lodash@4.17.10` (CVE-2019-10744, CVSS 9.8) lets a crafted JSON body inject onto `Object.prototype`; any route calling `_.merge` with request input poisons auth-flag checks.
> - **Session cookie missing `httpOnly`/`secure`** — `res.cookie()` is called without the hardening flags, so an XSS payload can read the session token.

### Diagnose
- Names the manifest, library versions, CVE numbers, `_.merge`, port 3000, `httpOnly` — none of which a PL can act on; they bury the point.
- "missing httpOnly" is a config-line finding, not an executive risk — it does not belong in the Verdict at all.
- The PL needs: *what can an attacker do to the business, and what broad class of practice is missing.*

### AFTER (product-owner altitude)

> - **Anyone can use the app without signing in** — it ships no authentication layer, so every function is open to unauthenticated callers on the public internet.
> - **Attackers can read or change customer data** — the application does not consistently keep one customer's data separate from another's.
> - **A normal account can gain administrator access** — important permissions are not checked reliably before sensitive actions are allowed.

### Regel
1. **Lead with the business outcome** ("anyone can use the app without signing in"), not the mechanism.
2. **Describe the missing control as a class** ("no authentication layer", "skips several standard practices"), not a config key.
3. **No config keys / versions / CVE / file:line / framework symbols / security acronyms** in `body` — the technical detail belongs in §6 and §8.
4. **A pure config-line ("missing httpOnly") is not a Verdict bullet** — fold it into a broader "hardened session handling" class or leave it to §6.
