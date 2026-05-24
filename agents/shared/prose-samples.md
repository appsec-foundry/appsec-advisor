# Report prose — worked Before/After pairs

> Companion to `prose-style.md`. That file states the rules; this file
> shows them applied to real prose. Each pair is a passage that was
> actually rendered into a threat-model report, the AI-flavored pattern
> it exhibited, the human-style rewrite, and the rule that follows.
>
> Loaded by the renderer and finalization agents before authoring
> `ms-verdict.json` and `ms-architecture-assessment.json` — Claude
> Sonnet imitates worked examples more reliably than it follows
> abstract rules.
>
> When a new AI-tell shows up in a real run, add it here as a pair —
> not as a new rule in `prose-style.md`. Rules without examples drift;
> examples don't.

---

## Pair A — MS Verdict Opening (`ms-verdict.json::verdict_prose`)

### BEFORE (95 Wörter, 5 Sätze, AI-flavored)

> 🔴 Not production-ready. OWASP Juice Shop is deliberately designed as a training target for security practitioners, embedding intentional weaknesses across every tier of its architecture. The application exposes multiple independent paths to full account and host compromise that require no elevated privilege or specialised tooling - a user with only a browser and repository read access can bypass authentication entirely. Closing the risk requires structural changes at the authentication, data-access, and secret-management layers, not a single-point patch.

### Diagnose
- "embedding intentional weaknesses across every tier of its architecture" — drei Nominalisierungen in einem Atemzug
- "exposes multiple independent paths to full account and host compromise" — Nominalstil; "compromise" als Substantiv
- "a user with only a browser and repository read access" — lange noun-phrase; ein Mensch schreibt "anyone"
- Schluss-Satz "Closing the risk requires structural changes at the X, Y, and Z layers, not a single-point patch" — typische AI-Kadenz: Triplet + "not a single X" Antithese

### AFTER (62 Wörter, 4 Sätze, menschlich)

> 🔴 Not production-ready. Juice Shop is a training target — intentional weaknesses live in every tier. Anyone with a browser and repo read access can take over admin accounts and the host server through several independent paths, none of which need elevated privilege or special tooling. Fixing this means rebuilding authentication, data access, and secret management — not patching a single bug.

### Regel
1. **Nominalisierungen auflösen**: "embedding weaknesses" → "weaknesses live"
2. **Triplet-Kadenz brechen**: nicht "X, Y, and Z layers" — sondern Verb-Form mit em-dash-Schluss
3. **"a user with only a browser…" → "anyone with…"**: kürzer, menschlicher
4. **Wortzahl-Reduktion ~30 %** ohne Inhaltsverlust

---

## Pair B — MS Verdict Closing (`ms-verdict.json::closing_prose`)

### BEFORE (37 Wörter, 1 Satz, AI-flavored)

> Nineteen mitigations are identified; replacing the hardcoded secrets with runtime-injected values, switching to parameterized database queries, and upgrading the password hashing algorithm address the highest-impact paths and are prerequisites for any production readiness evaluation.

### Diagnose
- "Nineteen mitigations are identified" — Passiv-Eröffnung
- triple-parallel "replacing... switching... upgrading..." — symmetrische Triplet, klassisch AI
- "are prerequisites for any production readiness evaluation" — Bürokraten-Deutsch; nominalisiert "prerequisite"

### AFTER (40 Wörter, 3 Sätze, menschlich)

> Nineteen mitigations follow. Three matter most: move secrets out of source, switch raw SQL to parameterized queries, replace MD5 password hashes. Without those three, production readiness is not on the table.

### Regel
5. **Aktiv statt Passiv** im Opener
6. **Kolon-Liste statt Triplet-Gerundium**: "X, Y, and Z" mit `-ing`-Formen → "X. Y. Z." mit Verb-Imperativ
7. **Punchline-Schluss**: konkretes Bild ("not on the table") statt Floskel ("are prerequisites for any production readiness evaluation")
8. **Kürzere Sätze**: 1 Satz → 3 Sätze, gleicher Inhalt, lesbarer

---

## Pair C — Crypto Weakness Description (`ms-architecture-assessment.json::weaknesses[0].description`)

### BEFORE (54 Wörter, 2 Sätze)

> A 1024-bit RSA private key, an HMAC secret, and a cookie-signing secret are all hardcoded as string literals in `lib/insecurity.ts`. These are repository-public values — anyone who clones the repo can sign arbitrary JWTs or forge session cookies without server access.

### Diagnose
Schon ziemlich gut — konkret, file-path drin, Punchline am Ende. Aber:
- "are all hardcoded" — Passiv
- "These are repository-public values" — Demonstrativpronomen-Opener + Kopulasatz; etwas stiff

### AFTER (45 Wörter, 2 Sätze)

> Three secrets live as hardcoded string literals in `lib/insecurity.ts`: a 1024-bit RSA private key, an HMAC secret, and a cookie-signing secret. Cloning the repo gives you everything needed to sign JWTs or forge session cookies — no server access required.

### Regel
9. **Punchline-Opener mit Zählung**: "Three secrets live as…" benennt den Skandal sofort
10. **Kolon statt Aufzählung-im-Subjekt**: erst die Aussage, dann der Beleg
11. **"You" als Subjekt** wenn natürlich: "Cloning the repo gives you everything…" liest sich wie ein Reviewer-Kommentar, nicht wie ein Compliance-Bericht. (Nur sparsam einsetzen, nicht als Standard.)

---

## Pair D — Authorization Weakness Description (`ms-architecture-assessment.json::weaknesses[3].description`)

### BEFORE (53 Wörter, 2 Sätze)

> Several REST endpoints exposed via `finale-rest` accept mass-assignment updates to privileged model fields; the product update endpoint at `server.ts:361` has no authentication middleware; and Angular route guards enforce access control only in the browser without a server-side equivalent. Authorization is inconsistent across the API surface.

### Diagnose
- "Several" — vage; wieviele genau?
- Drei Semikolon-getrennte Klauseln in einem Satz — symmetrisch, formell
- Schluss-Satz "Authorization is inconsistent across the API surface" — generische AI-Schluss-Kadenz "X is Y across Z"

### AFTER (51 Wörter, 4 Sätze)

> `finale-rest` exposes REST endpoints that accept mass-assignment to privileged model fields. The product update at `server.ts:361` runs without auth middleware. Angular route guards run only in the browser; there is no server-side equivalent. Three different gaps, one missing piece: server-side authorization as a pattern.

### Regel
12. **Variation Satz-Länge**: 4 Sätze mit Längen 11/7/13/13 — Rhythmus statt Symmetrie
13. **Schluss mit Diagnose statt Generalisierung**: nicht "X is inconsistent across Y" — sondern "die fehlende Pattern ist X". Benennt den Root-Cause.
14. **Drop "Several"**: entweder Zahl nennen oder die Klausel umbauen sodass die Zahl im Kontext steht

---

## Pair E — Operational Strengths Intro (out of Iteration 1 — Referenz für später)

### BEFORE (61 Wörter, 2 Sätze)

> Despite the structurally deficient design, the project carries a baseline of categorical strengths. The table below groups individual controls into broad-stroke clusters (full per-control breakdown in [Section 7](#7-security-architecture)). Only clusters that genuinely rate as a strength (Adequate or Partial) appear here - clusters demoted to Weak by open Critical/High findings in their defensive remit are excluded from this section and live in [§7](#7-security-architecture) instead.

### Diagnose
- "Despite the structurally deficient design" — formelle contrastive Eröffnung
- "carries a baseline of categorical strengths" — "carries a baseline of" = Bürokraten-Deutsch
- "The table below groups individual controls into broad-stroke clusters" — Meta-Narration über die Tabelle (Leser sieht die Tabelle)
- "broad-stroke clusters" — vague Adjektiv-Substantiv-Kombi
- Schluss-Satz: 36 Wörter, 3 verschachtelte Klauseln

### AFTER (44 Wörter, 3 Sätze)

> Not everything is broken. The clusters below list controls that actually work (Adequate or Partial). Anything weakened by an open Critical/High finding moved to [§7](#7-security-architecture) instead — appearing here would be misleading.

### Regel
15. **Drop Meta-Narration**: kein "the table below shows…" — die Tabelle zeigt sich selbst
16. **Drop formal contrastive opener**: "Despite the X, Y" → kurzer direkter Satz
17. **Drop empty adjective-noun-combos**: "broad-stroke clusters", "categorical strengths", "structurally deficient design"
18. **Begründung am Ende statt Hierarchie-Erklärung**: "appearing here would be misleading" sagt das Warum in 4 Wörtern

---

## Abgeleitetes Vocabulary

### Banned (in Polisher-Output, weil AI-Tells)

Adjektive: `robust`, `comprehensive`, `holistic`, `seamless`, `crucial`, `vital`, `key` (als modifier), `categorical`, `broad-stroke`, `structurally deficient`

Verben: `leverage`, `facilitate`, `ensure`, `enable`, `embed` (außer im Sinn von "embedded systems"), `carry a baseline of`

Quantoren ohne Zahl: `several`, `multiple`, `various`, `numerous`, `many`

Transitions: `furthermore`, `moreover`, `additionally`, `in essence`, `in summary`, `notably`, `importantly`

Meta-Floskeln: `it is worth noting`, `it should be noted`, `it is important to note`, `the table below shows`, `as can be seen`

Generische Schluss-Kadenzen: `X is Y across the Z`, `X requires Y at the A, B, and C layers`, `X are prerequisites for any Y`

### Preferred Idioms (positive)

- **Em-dash für Punchline-Schluss**: `… — no server access required.`
- **Kolon für Listen im Satz**: `Three matter most: X, Y, Z.`
- **Variable Satz-Länge**: 3-15 Wörter, gemischt
- **Diagnose-Schluss**: "the missing piece is X" / "the pattern that's absent is X"
- **Zahl statt Quantor**: "three", "four", "every", "all" — nicht "several", "multiple"
- **Aktiv-Voice** für Opener
- **Imperativ-Verben in Mitigation-Listen**: "move", "switch", "replace" — nicht "moving", "switching", "replacing"

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
