# Analyse: §3 „Attack Steps" — Formatierung, Aktor-Stimme, Ablauf-Kohärenz

**Datum:** 2026-07-19
**Auslöser:** User-Report an `insecure-python-app` Run (3 Screenshots, 3 Findings)
**Betroffener Generator:** `scripts/walkthrough_renderer.py` → `render_attack_steps()` (Z. 905–1001)
**Status:** Umgesetzt 2026-07-19 (außer D5, siehe unten).

## Umgesetzt

| Datei | Änderung |
|---|---|
| `schemas/threat-model.output.schema.yaml`, `schemas/stride.schema.yaml` | optionales `threats[].attack_steps` (2–5 Einträge) |
| `agents/appsec-stride-analyzer.md` | Abschnitt „Authoring `attack_steps`" — 7 Regeln + Beispiel; Pflicht für Critical |
| `scripts/walkthrough_renderer.py` | `attack_steps` bevorzugt; `_NON_STEP_LEAD_RE`-Filter; `_normalize_actor_voice`; Prepend-Gate mit Zwei-Schritt-Floor; lokale Call-Regex entfernt (halbformatierte Nester); Delegation an den zentralen Formatter |
| `scripts/apply_prose_fixes.py` | `_merge_split_code_spans` (Subscript/Query/Call-Args/Range/Assign); neue Token-Klassen URL, IPv4, JSON-Literal, snake_case, SCREAMING_SNAKE, dunder, Call-mit-Argumenten; `_inside_bare_call`-Guard gegen Halbformatierung |
| `scripts/assets/print.css` | Pandoc/Skylighting-Override — lange Fence-Zeilen brechen um statt zu scrollen |
| `tests/test_attack_step_quality.py` | 38 Regressionstests, alle Strings verbatim aus dem gemeldeten Run |
| `tests/test_prompt_token_bounds.py` | Bound für den Analyzer-Prompt 14.900 → 15.600 |

Volle Suite: **9.884 passed, 93 skipped**. Lint/Format: grün.

## Verifikation (2026-07-19, zweiter Durchgang)

Der Verifikationslauf fand **sechs echte Defekte**, die der erste Durchgang
übersehen hatte — Einzelstring-Tests können sie prinzipiell nicht zeigen:

| # | Defekt | Nur sichtbar durch |
|---|---|---|
| 1 | `ruff format` rot | `make lint` |
| 2 | Formatter **nicht idempotent** über ein ganzes Dokument: permissiver Span-Kopf paarte die *schließende* Backtick einer Span mit der *öffnenden* der nächsten und verschluckte die Prosa dazwischen | zwei Spans in einer Zeile |
| 3 | Merge lief nur *vor* den Wrapping-Passes — von ihnen erzeugte Spans bekamen ihren Tail erst im nächsten Aufruf | Reihenfolge im selben Aufruf |
| 4 | Englische Plural-Klammern als Call gewertet: `` `weakness(es)` ``, `` `finding(s)` ``, `` `point(s)` `` — 9 Fälle im echten Report | Lauf über das echte Dokument |
| 5 | Markdown-Emphasis verschluckt: `` `pentest-tasks.yaml`._ `` → `` `pentest-tasks.yaml._` `` | echtes Dokument |
| 6 | Merge-Tails durften Backticks enthalten und liefen so in die nächste Span hinein | vorbeschädigte Zeile im echten Report |

Alle sechs gefixt und als Regressionstests festgenagelt (`TestSpanPairing`).

Zusätzlich end-to-end verifiziert statt angenommen:

- **Schema-Arme**: `attack_steps` optional/null akzeptiert; 1 Schritt, zu kurze
  Schritte, 6 Schritte, Überlänge werden abgelehnt.
- **Merge-Durchreichung**: `attack_steps` in eine echte `.stride-*.json`
  injiziert, `collect` + `finalize` gefahren — Feld erreicht `T-002` in
  `.threats-merged.json`. (Vorher nur analog zu `evidence_summary` geschlossen.)
- **CSS-Kaskade**: echter `export_html.py`-Lauf. Pandoc emittiert
  `pre > code.sourceCode { white-space: pre }`, `code.sourceCode > span
  { display: inline-block }` und `div.sourceCode { overflow: auto }` bei
  Position 581–1074; unsere Overrides stehen bei 5041–5201, also *danach*, und
  in keinem `@media`-Block. Bei gleicher Spezifität gewinnen damit unsere.
- **Schadensbilanz am echten Report**: 176 Änderungen, 126 Zeilen, 87 neue
  Spans — alle einzeln gesichtet. Keine verschachtelten Backticks, keine
  Änderung der Zahl unbalancierter Zeilen (164 → 164), keine Zeile mit
  unbalancierten Backticks angefasst (0), idempotent über drei Durchläufe.
- **§3-Kontrakt** über alle 15 Critical-Findings: keine Ein-Schritt-Liste, kein
  wiedereingeführtes „An attacker", keine unbalancierte Span. 0 Verstöße.

**Nicht umgesetzt: D5** (Wort „password" wird vom Secret-Masker zerstört). Eigener
Bug in `compose_threat_model.py:12516`, unabhängig von §3 — siehe unten.

Die Merge-Durchreichung von `attack_steps` brauchte keinen Code: `merge_threats.py`
reicht STRIDE-Felder unverändert durch (verifiziert an `evidence_summary`).
Wirksam wird das Feld erst bei einem neuen Scan; bestehende Modelle laufen über
den gehärteten Fallback-Pfad.

---

## 0. Kernursache (eine Zeile)

```python
sentences = _split_sentences(threat["scenario"])
body.extend(sentences[:MIN_ATTACK_STEPS])       # Z. 950, 983
```

`scenario` ist ein **Erklär-Absatz** (speist auch die §8 „Issue"-Zelle), keine Schritt-Liste.
Ein Erklär-Absatz mechanisch in `1. 2. 3.` umzunummerieren kann prinzipiell keine
angreifer-folgbare Sequenz ergeben — Diskurskonnektoren (`Critically,` `Because,`
`Additionally,` `They then`) setzen Absatz-Kontext voraus und lesen sich als
Nummernpunkt wie Non-Sequiturs. Alle drei User-Findings sind Symptome davon.

---

## 0.5 Zielbild (User-Vorgabe 2026-07-19)

> „der ablauf soll wirklich stimmig und klar und knapp beschrieben werden,
> ausgehend vom angreifer"

Daraus ein prüfbarer Kontrakt für jeden §3-Schritt:

1. **Angreifer im Subjekt.** Jeder Schritt beginnt mit dem Aktor, nicht mit dem Code.
   Verboten: „The function X declares…", „Server code that consumes…", „The endpoint requires…".
2. **Handlung, kein Zustand.** Jeder Schritt ist ein Verb, das der Angreifer ausführt
   (`sendet`, `ersetzt`, `signiert`, `liest ab`). Keine Begründungen, keine Caveats,
   keine Vorbedingungen als eigener Punkt.
3. **Chronologie.** Schritt *n+1* ist erst möglich, nachdem *n* geschah. Recon → Payload →
   Wirkung. Prüfbar: Schritte vertauschen muss den Text kaputt machen.
4. **Knapp.** Ein Satz pro Schritt, ≤ ~200 Zeichen. Der Defekt-Nachweis (welche Zeile,
   welches fehlende Control) gehört in die `**Source:**`-Zeile und §8, nicht in den Schritt.
5. **Konsistente Aktor-Nennung.** Erstnennung „An attacker", danach „the attacker".
6. **Alle Code-Tokens in Backticks**, ganze Tokens, keine zerrissenen Spans.

Punkte 1–4 sind **inhaltlich** und daher nur über Stufe 2 (autorierte `attack_steps`)
erreichbar. 5–6 sind Stufe 1.

### Beispiel — Block „Mass Assignment" (md:434–436)

**Ist:**
```
1. The attacker crafts a request targeting the weak spot at `insecure_python_app/views.py:229`.
2. Server code that consumes `request.data`['role'] / ['is_staff'] etc. without a serializer allowlist trusts the client.
3. An attacker adds {"is_staff": true} to the request to escalate.
```
Regelverstöße: 1 dupliziert 3 (D4) · 2 hat Code als Subjekt (Regel 1) und zerrissenen
Span (Regel 6) · 3 wechselt den Artikel (Regel 5) und lässt JSON nackt (Regel 6).

**Soll:**
```
1. An attacker registers a normal account and authenticates against the profile API.
2. The attacker replays the profile-update request with `{"is_staff": true, "role": "ADMIN"}` added to the JSON body.
3. `views.py:229` passes the body straight into the model, so the attacker's account is now staff — every admin-gated view is open.
```

### Beispiel — Block „Hardcoded JWT Key" (md:592–594)

**Ist:** Schritt 3 macht den Code zum Subjekt („The verify_signed_jwt function … will accept").

**Soll:**
```
1. An attacker reads `JWT_SIGNING_KEY = b'local-demo-hardcoded-jwt-key'` from the public repository at `auth.py:18`.
2. The attacker signs a token with header `{"alg":"HS256"}` and payload `{"sub":"admin","uid":1,"role":"ADMIN"}` using that key.
3. The attacker sends it as a bearer token; `verify_signed_jwt` (`auth.py:78-79`) accepts it and the attacker holds admin.
```

---

## 1. Belegte Defektklassen (dieser Run, `docs/security/threat-model.md`)

### D1 — Code-Tokens unformatiert / Spans zerrissen

`_format_step_code()` (Z. 879–902) deckt: `file:line`, `param="…"`, SQL, `foo.bar()`.
Es fehlen fünf Klassen, alle im Run belegt:

| # | Klasse | Beleg (md-Zeile) | Ist | Soll |
|---|---|---|---|---|
| a | **Subscript-Fortsetzung** nach Code-Span | 435 | ``` `request.data`['role'] / ['is_staff'] ``` | ``` `request.data['role']` / `['is_staff']` ``` |
| b | **JSON-Literale** | 436, 593, 515, 552 | `{"is_staff": true}`, `{"alg":"HS256"}`, `{"sub":"admin","uid":1,"role":"ADMIN"}`, `{"user_id": N}` — alle nackt | Backticks |
| c | **Query-String-Fortsetzung** | 396, 2009 | ``` `/api/legacy-admin/audit`?token=<crafted> ``` | ``` `/api/legacy-admin/audit?token=<crafted>` ``` |
| d | **Bare Funktions-Identifier** (ohne `()`) | 397, 594, 672 | `read_unsigned_jwt_claims`, `verify_signed_jwt`, `require_signed_jwt` nackt — **im selben Listenpunkt** neben korrekt gesetztem `` `auth.py:84` `` | Backticks |
| e | **Zuweisungs-Wert-Fortsetzung** | 592 | ``` `JWT_SIGNING_KEY` = b'local-demo-hardcoded-jwt-key' ``` | Wert mit in den Span |
| f | **String-Literale** | 635 | `SharedPassword123`, `WarehouseAdmin!` nackt | Backticks |

(a), (c), (e) sind **derselbe Bug** wie der bereits reparierte `_STEP_DOTTED_MERGE_RE`
(Z. 872): das LLM backtickt nur den Kopf eines Tokens, die Fortsetzung fällt raus.
Es existiert bisher nur der `.member`-Merge — `[…]`, `?…`, `= …` fehlen.

### D2 — Aktor-Stimme inkonsistent

| md-Zeile | Subjekt |
|---|---|
| 434 | „**The** attacker crafts…" ← Template-Fallback, hartkodiert |
| 436 | „**An** attacker adds…" ← Szenario-Prosa |
| 593 | „**They** then construct…" |
| 397, 513, 634 | *kein Aktor* — Code ist Subjekt |

Der Template-Fallback (Z. 965–967) sagt immer „The attacker" und wird **vorangestellt**
(Z. 1000). Ergebnis im Mass-Assignment-Block: bestimmter Artikel bei Erstnennung,
unbestimmter bei Zweitnennung — genau verkehrt herum. Das ist der vom User
gemeldete Punkt.

### D3 — Sätze, die keine Schritte sind (Hauptursache für „liest sich nicht wie ein Fluss")

Belege aus diesem Run:

- **Statische Code-Beschreibung als Schritt 1** — in 6 von 8 Blöcken:
  „The function `unsafe_find_orders_by_owner_email` at `db.py:461-469` interpolates…" (472),
  „The function `update_user_mass_assignment` at `db.py:254-270` declares…" (513),
  „Server code that consumes `request.data`… trusts the client." (435)
  → beschreibt den *Defekt*, nicht eine *Angreifer-Handlung*.
- **Reine Begründung als Schritt 2**: „Critically, `role` and `admin` are security-bearing
  columns — `role` controls application-level authorisation checks…" (514)
- **Einschränkender Nachsatz als Schritt 3**: „Because SQLite's `execute` supports only
  single statements, multi-statement injection is not available, but…" (474)
  → ein Analyse-Caveat, chronologisch nirgends verortbar.
- **Vorbedingung als Schritt**: „The endpoint requires no authentication." (634)

Ein Leser, der „1., 2., 3." sieht, erwartet *tue dies, dann das*. Er bekommt
*Defektbeschreibung → Begründung → Einschränkung*.

### D4 — Template-Voranstellung bricht Chronologie

Mass-Assignment-Block: Szenario hat nur 2 Sätze → 1 Template-Schritt wird vorangestellt
(Z. 997–1000). Ergebnis:

```
1. The attacker crafts a request targeting the weak spot at views.py:229.   ← Template
3. An attacker adds {"is_staff": true} to the request to escalate.          ← Szenario
```

Schritt 1 und 3 sind derselbe Vorgang, doppelt erzählt, mit wechselndem Artikel.
Der Prepend-Kommentar (Z. 991–996) begründet das Voranstellen mit Recon-Schritten
aus CWE-Templates — hier greift die Begründung nicht, weil der Generic-Fallback
kein Recon-Schritt ist, sondern der Angriff selbst.

### D5 — Angrenzender, separater Bug: Wort „password" wird zerstört

Nicht Teil der User-Frage, aber im selben Report und schwerwiegender:

```
md:553   … without knowing any user's pass**** (9 chars)
md:822   `hashlib.sha256(pass**** (9 chars)encode()).hexdigest()`
md:1269  … exposes JWT signing key and database pass**** (9 chars)
```

10+ Vorkommen, teils **innerhalb von Code-Spans**. Quelle: `compose_threat_model.py:12516`
(`secret_scan.mask_text(md)` über das gesamte gerenderte Markdown). Der gelernte
„Secret" ist das Seed-Passwort aus `db.py:124`; die Ersetzung läuft ohne
Wortgrenzen- und ohne Wörterbuch-Guard über die Prosa.
`redact_known_secrets.py:110` (`new_text.replace(value, mask)`) hat dieselbe Schwäche —
hier war `total_redactions: 0`, der Schaden kam aus `mask_text`.
**Eigenes Ticket wert.**

---

## 2. Empfehlung — zwei Stufen

### Stufe 1 — Renderer-lokal, deterministisch, testbar (schließt D1, D2, D4)

Alles in `walkthrough_renderer.py`, keine Schema-/Agent-Änderung, snapshot-testbar.

**1a. Span-Merges (FP-Risiko ~0 — repariert nur bereits existierende Spans):**

```python
_STEP_SUBSCRIPT_MERGE_RE = re.compile(r"`([^`\n]+)`((?:\[[^\]\n]{1,40}\])+)")   # `request.data`['role']
_STEP_QUERY_MERGE_RE     = re.compile(r"`([^`\n]+)`(\?[\w=&<>%.:/-]{1,80})")     # `/api/x`?token=<crafted>
_STEP_ASSIGN_MERGE_RE    = re.compile(r"`([A-Z_][A-Z0-9_]*)`(\s*=\s*)(b?'[^'\n]{1,80}'|\"[^\"\n]{1,80}\")")
```

**1b. JSON-Literale backticken** (neuer Vorwärts-Pass, nur balancierte Ein-Zeilen-Objekte
mit mindestens einem `"key":`):

```python
_STEP_JSON_RE = re.compile(r'(?<![`\w])(\{\s*"[\w.-]+"\s*:[^{}\n]{0,120}\})(?!`)')
```

**1c. Bekannte Symbole backticken** — *nicht* per Heuristik, sondern aus Fakten:
Identifier-Namen aus `threat.evidence[].excerpt`, `threat.title` und den verlinkten
`mitigations[].title` einsammeln und in den Schritten wortgenau backticken. Das löst
(d) und (f) ohne generisches „snake_case = Code"-Raten (das würde `is_staff` in Prosa
falsch treffen).

**1d. Aktor-Normalisierung** — neue Funktion `_normalize_actor_voice(steps: list[str])`:
erste Aktor-Nennung → „An attacker", jede weitere → „the attacker"; führendes
„They "/„He "/„She " → „The attacker ". Rein string-lokal, idempotent.

**1e. Template-Prepend nur noch, wenn das Szenario keine Angreifer-Handlung enthält**
(Z. 997–1000): wenn `any(re.search(r"\battacker\b", s) for s in sentences)`, dann
**nicht** prependen, sondern die Liste bei 2 Schritten belassen. `MIN_ATTACK_STEPS`
ist ein Minimum für die Contract-Zeilenzahl — die wird durch Sequence Diagram +
Key takeaway ohnehin erfüllt (siehe Kommentar Z. 59–62).

### Stufe 2 — strukturell, der eigentliche Fix (schließt D3)

D3 ist mit Regex **nicht** lösbar. „Critically, role and admin are security-bearing
columns" ist ein grammatikalisch einwandfreier Satz — nur eben kein Schritt.

**Vorschlag:** optionales Feld `attack_steps: [str]` (3–4 Einträge) an `threats[]`:

- `schemas/stride.schema.yaml` (Z. ~127 `required`-Block, als *optional* ergänzen)
- `schemas/threat-model.output.schema.yaml` (Z. ~544, neben `scenario`)
- `agents/appsec-stride-analyzer.md`: Autoren-Anweisung — 3 Schritte,
  Angreifer im Subjekt, Imperativ-Chronologie, keine Begründungen, keine Caveats.
  `scenario` bleibt unverändert der Erklär-Absatz für §8.
- `render_attack_steps()`: `threat["attack_steps"]` bevorzugen, sonst heutiger
  Szenario-Split als Fallback.

**Fallback härten** (greift auch ohne Stufe 2 sofort): Sätze verwerfen, die mit einem
Diskurskonnektor oder einer Zustandsbeschreibung öffnen —

```python
_NON_STEP_LEAD_RE = re.compile(
    r"^\s*(?:Critically|Because|Additionally|Moreover|Note that|While|Although|"
    r"However|This (?:means|allows)|The (?:endpoint|function|code) (?:requires|is|has))\b",
    re.IGNORECASE)
```

— und erst danach auf `MIN_ATTACK_STEPS` schneiden. Das hätte in diesem Run
md:474, md:514 und md:634 entfernt.

---

## 3. Bewertung / Reihenfolge

| Maßnahme | Aufwand | Risiko | Wirkung auf User-Report |
|---|---|---|---|
| 1a Span-Merges | S | sehr niedrig | Screenshot 1 + 3 gelöst |
| 1b JSON | S | niedrig | Screenshot 1 + 3 gelöst |
| 1d Aktor-Stimme | S | niedrig | Punkt „An/the attacker" gelöst |
| 1e Prepend-Gate | XS | niedrig | Doppel-Schritt weg |
| Fallback-Härtung (`_NON_STEP_LEAD_RE`) | S | mittel¹ | „liest sich nicht wie Fluss" ~60 % |
| 1c Symbol-Backticks | M | niedrig | Restliche Inkonsistenz |
| **Stufe 2 (`attack_steps`)** | **L** | niedrig | „liest sich nicht wie Fluss" vollständig |

¹ Einziges Risiko: bei kurzem `scenario` fallen unter 3 Schritte — dann greift wieder
der Template-Fallback. Muss zusammen mit 1e abgestimmt werden.

**Empfehlung (nach User-Vorgabe 0.5 revidiert):**

**Stufe 2 ist der eigentliche Auftrag, nicht das Optional.** Der User verlangt einen
Ablauf „ausgehend vom Angreifer" — Regeln 1–4 aus §0.5 sind inhaltlich und lassen sich
aus einem Erklär-Absatz nicht per Regex herausrechnen. Solange die Schritte aus
`scenario` geschnitten werden, bleibt Schritt 1 eine Defektbeschreibung.

Reihenfolge:
1. **Stufe 2** — `attack_steps: [str]` in Schema + `appsec-stride-analyzer.md`,
   Autoren-Kontrakt = §0.5 Regeln 1–5. Renderer bevorzugt das Feld.
2. **Stufe 1a/1b/1c** — Code-Formatierung. Nötig auch mit Stufe 2, weil die
   Schritte weiter LLM-authoriert sind und dieselben Span-Fehler produzieren können.
3. **1d/1e + Fallback-Härtung** — sichert die Alt-Modelle und den Fallback-Pfad
   (Findings ohne `attack_steps`, z. B. aus inkrementellen Läufen).
4. **qa_checks-Regel** — §3-Schritte gegen §0.5 Regel 1 prüfen: Schritt beginnt nicht
   mit `The (function|endpoint|code|server)` / `Server code`. Deterministisch, verhindert
   Rückfall.

D5 separat, unabhängig von §3.

---

## 4. Testverankerung

`tests/test_walkthrough_renderer.py` existiert. Ergänzen:
- Je ein Regressionstest pro D1-Klasse (a–f) mit den exakten Strings aus diesem Run.
- Aktor-Idempotenz: `_normalize_actor_voice(_normalize_actor_voice(x)) == _normalize_actor_voice(x)`.
- Golden-Snapshot der 8 §3-Blöcke aus `insecure-python-app` als Fixture.
