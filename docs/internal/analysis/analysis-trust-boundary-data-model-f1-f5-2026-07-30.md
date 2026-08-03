# Analyse: Trust-Boundary-Datenmodell — fünf Designfragen (F1–F5)

Datum: 2026-07-30 · Repo: appsec-advisor@dev · Belegdaten: juice-shop-Lauf in
`/home/mrohr/juice-shop/docs/security/` (2026-07-30, 17:38–19:11)

## 0. Verifikationsstand und Abweichungen von der Faktenliste

Alle sechs Fakten wurden am Code bzw. an den Lauf-Artefakten nachgeprüft. Vier
Abweichungen bzw. Präzisierungen:

1. **F5-Prämisse nicht belegt (Gegenteil belegt).** Die Begründung
   „`enforcement_point` ist optional, damit `--resume`-Läufe mit
   Bestandsartefakten nicht brechen" existiert nirgends im Repo. Das Feld wurde
   in `f5cd00a5` („Consolidate trust boundaries at the enforcement point")
   von Anfang an als optional eingeführt; `grep -rn resume` über
   `prepare_trust_boundary_context.py`, `build_trust_boundary_assessment_input.py`
   und das Analyst-Agentfile liefert null Treffer. Die tatsächlich dokumentierte
   Begründung ist eine Modellierungsentscheidung
   (`prepare_trust_boundary_context.py:1333-1339`):
   > "Separation must be justified, not consolidation. A declared
   > `enforcement_point` IS the justification … Candidates that name none fall
   > back to grouping by the crossing itself."
2. **Fakt 6 („gruppiert nach from/to/Richtung"):** Der Fallback-Schlüssel ist
   `("crossing", from, to, crossing_class)` (`:1340-1347`); ein `direction`-Feld
   existiert auf Boundaries nicht (in den Lauf-Artefakten tragen nur die 12
   `data_flows` eine `direction`). `crossing_class` ∈ {ingress, egress, internal}
   ist aus from/to abgeleitet (`:1267-1272`) — im Fallback-Schlüssel redundant.
   Die eigentlich überraschende Eigenschaft steckt im **Point-Schlüssel**:
   `("point", normalisierter-string, crossing_class)` enthält from/to **nicht** —
   zwei Kandidaten mit unterschiedlichen Komponentenpaaren, aber gleichem
   Enforcement-Point-String und gleicher Klasse mergen zu einer Boundary; der
   Survivor behält die Endpunkte von `members[0]`.
3. **Fakt 5 ist dreiteilig, nicht zweiteilig.** Die Elevation-Eligibility
   verlangt `confidence == "confirmed"` UND `from == "external"` UND
   `to == ref.origin_component_id` (`triage_compute_ranking.py:611-620`). Die
   dritte Bedingung ist für F1 tragend (siehe unten).
4. **Die Belegdaten zeigen den Vorher-Zustand.** Im Lauf ist `enforcement_point`
   in allen 6 Kandidaten/Boundaries abwesend und tb-1 trotz server.ts-Zitat nur
   `inferred` — beides konsistent damit, dass der Lauf die vier Commits (Feld +
   Konsolidierung + Aufwertung) noch nicht enthielt. Die Abwesenheit des Felds
   ist also **kein** Beleg dafür, dass der Analyst die neue Anweisung ignoriert;
   dafür gibt es schlicht noch keinen Lauf.

Weitere für die Fragen relevante, verifizierte Randbefunde:

- `enforcement_point` ist **write-only**: bei der Promotion wird nur
  `("name","from","to","kind","assumption","evidence","confidence")` kopiert
  (`prepare_trust_boundary_context.py:1535-1550`), und das kanonische Schema
  (`schemas/fragments/trust-boundaries.schema.json`, `additionalProperties:false`)
  kennt das Feld nicht. Die Gruppierungsentscheidung ist im fertigen Modell
  nicht nachvollziehbar und bei Re-Runs nicht rekonstruierbar.
- `kind` wird **ausschließlich** in `prepare_trust_boundary_context.py`
  behavioral konsumiert (Focus-Tier `:861-873`, Dispatch-Ranking `:981-983`,
  Same-Deployable-Coercion `:1326,1331`, Privilege-Re-Anchoring `:660`,
  Ingress-Folding `:676`, Normalisierungs-Fallback auf `network` `:230`).
  Rendering, Triage, QA, Exporte behandeln es als opaken String.
- Die Richtungskorrektur (`_looks_inbound` → `_evidence_line`) ist
  **zeilengranular**; die Confidence-Aufwertung (`_ingress_is_evidenced` →
  `_file_registers_routes`, erste 512 KB der Datei, `line` ignoriert) ist
  **dateigranular**. Beide leben in derselben Schleife (`:1303-1320`).
- Elevation: genau +1 Severity-Rang, hart bei High gekappt, nur effektive
  Severity (nie Raw Risk/CVSS), unterdrückt bei `evidence_check` ∈
  {refuted, ambiguous}, läuft vor den CWE-Caps
  (`triage_compute_ranking.py:477-492`). Im Lauf:
  `findings_elevated_via_external_boundary: 0` (alle 10 Elevations kamen aus
  Ketten/Keystones).
- Lauf-Katalog: tb-1 network (external→backend-api, inferred), tb-2 process
  (backend-api→sqlite-database, inferred), tb-3 identity (external→auth-service,
  inferred), tb-4 build, tb-5 third-party (chat-service→external, **confirmed**,
  einzige mit Findings: F-022/F-032), tb-6 third-party. Alle 19 Signal-
  Dispositionen `boundary`; `same-trust` nie verwendet; Kandidat→tb 1:1, keine
  Konsolidierung fand statt.
- Komponentenmodell: kein `runtime`/`deployable`/`zone`-Feld; nur
  `deployment_zones` (Reachability-Vokabular) und `paths`-Globs. Die
  Same-Deployable-Primitive ist Glob-Containment (`_same_deployable`/
  `_paths_contained`, `:1217-1238`) und lehnt Zonen mit dokumentierter
  Begründung ab (juice-shop zonte sqlite als `peer-service`, obwohl in-process).
  Docker/Compose wird nirgends zu einer strukturierten Deployable-Zuordnung
  ausgewertet.

---

## F1 — Boundary am Deployable statt am Komponentenpaar?

**Empfehlung: Nein — die Boundary-Identität nicht ans Deployable hängen.
Stattdessen das Deployable als zusätzliche Dimension in den
Fallback-Gruppierungsschlüssel aufnehmen: für Ingress-Kandidaten ohne
`enforcement_point` gruppiere nach `("crossing", from, deployable(to),
crossing_class, kind)` statt `("crossing", from, to, crossing_class)`.**

Begründung:

1. **Das belegte Problem ist ein Gruppierungsproblem, kein Identitätsproblem.**
   external→backend-api und external→auth-service bleiben getrennt, weil der
   Fallback-Schlüssel `to` wörtlich vergleicht. Deployable-bewusstes `to` im
   Schlüssel behebt genau das, ohne das restliche Modell anzufassen.
2. **Identität am Deployable bricht drei verifizierte Mechanismen:**
   - Die Elevation-Bedingung `to == origin_component_id`
     (`triage_compute_ranking.py:618`) — ein auth-service-Finding, das auf eine
     gemergte Boundary mit `to: backend-api` zeigt, fiele durch. Der Merge würde
     Elevations **verlieren**, nicht gewinnen, solange der Check nicht
     containment-bewusst wird („origin ⊆ deployable(to)").
   - Die Adjacency-Auswahl für den STRIDE-Dispatch und die
     `validate_finding_boundary_refs`-Kette (non-adjacent origin → Ref wird
     verworfen, `prepare_trust_boundary_context.py:1105-1180`): auth-service
     wäre nicht mehr adjazent und dürfte die Boundary gar nicht referenzieren.
   - Die `from`/`to`-Pattern aller drei Schemata plus Rendering/Figure-1, die
     Komponenten-IDs erwarten.
   Ein Deployable-`to` erzwingt also entweder ein neues Endpunkt-Konzept in
   Schemata, Dispatch, Validierung, Triage und Renderer — oder
   Containment-Checks an jeder dieser Stellen. Das ist viel Migrationsfläche
   für ein Problem, das der Gruppierungsschlüssel allein löst.
3. **`kind` muss in den erweiterten Schlüssel**, sonst über-merged das
   Deployable-Fallback: tb-1 (network) und tb-3 (identity) gehen in denselben
   Prozess, sind aber inhaltlich verschiedene Übergänge — die OAuth-Assertion
   wird von einem anderen Kontrollmechanismus entschieden als die generische
   HTTPS-Ingress. Die gewünschte Konsolidierung betrifft *gleichartige*
   Querungen in denselben Prozess. (Genau hier trägt das Beispiel der Frage
   nur halb: die Getrennt-Haltung von tb-1/tb-3 ist kein Konsolidierungs-
   versagen, sondern korrekt — nur der Weg dorthin, wörtliche to-Gleichheit
   statt Deployable+kind, ist zufällig richtig.)
4. **Deployable-Bestimmung: transitive Glob-Containment-Hülle, kein
   Dockerfile/Compose-Parsing.** `_paths_contained` existiert, ist getestet und
   hat den juice-shop-Fall richtig entschieden, während `deployment_zones`
   nachweislich in die Irre führt (peer-service-Zonung der in-process-DB).
   Compose-Parsing wäre neue, fragile Maschinerie und beschreibt
   Deployment-*Varianten*, nicht notwendig die des bewerteten Standes.
   Repräsentant der Hülle: die Wurzelkomponente (Superset-Globs, hier
   backend-api mit `server.ts`). Komponenten, die in keiner oder mehrerer
   Hüllen liegen: keine Zuordnung, konservativ getrennt lassen — konsistent
   mit der dokumentierten Politik „under-merging stays visible and is fixable
   next run".
5. Optional, billig, auditierbar: das ermittelte Deployable als
   Anzeige-Attribut (`deployable: backend-api`) in den kanonischen Katalog
   schreiben, damit ein Leser sieht, *warum* zwei Signale eine Boundary wurden.

## F2 — Ist eine In-Process-Durchsetzungsschnittstelle eine Trust Boundary?

**Empfehlung: Kein separates Top-Level-Konzept. Der `kind`-Wert (nach F4: die
Mechanismus-Achse) ist die richtige Lösung — aber das Rendering muss die
Kategorie ehrlich ausweisen.**

Begründung:

1. Modellierungstheoretisch hat die Frage recht: tb-2 ist kein
   Trust-*Übergang* (kein Wechsel von Identität, Privileg, Mandant oder
   Betreiber; die eigene Assumption sagt „no separate network hop"). Es ist
   eine Durchsetzungsschnittstelle (ORM/Parametrisierung) *innerhalb* einer
   Trust-Domäne.
2. Aber der verifizierte Schaden des Status quo ist rein präsentational.
   `kind: process` kann nichts Falsches auslösen: die Elevation verlangt
   `from == "external"`, das Focus-Tier stuft process nicht in die
   privilegierten Klassen, und kein anderer Konsument verzweigt auf kind. Die
   Boundary liefert dem STRIDE-Analyzer Kontext und den Datenzugriffs-Findings
   einen Ankerpunkt — das „Werkzeug-Argument" kostet im Risikokanal
   nachweislich nichts (0 Elevations, tb-2 hat 0 Findings).
3. Ein Parallelkonzept („enforcement interface" neben „trust boundary")
   verdoppelt dagegen Schema, Katalog, Dispatch-Kontext, QA und Rendering für
   eine Unterscheidung, die ein Feldwert tragen kann. Das steht in keinem
   Verhältnis.
4. Was fehlt, ist Ehrlichkeit im Artefakt: der §1-Katalog zeigt tb-2
   gleichrangig als „Trust Boundary". Konkret: process-Rows im Katalog als
   „internal enforcement interface — no trust transition" kennzeichnen
   (Render-Detail, eine Stelle: `compose_threat_model.py` §1-Tabelle). Mit der
   F4-Migration löst sich das terminologisch von selbst: `surface: in-process`
   plus leere Transition-Achse *ist* die explizite Aussage „Schnittstelle ohne
   Trust-Übergang".

## F3 — Ist die dateigranulare Confidence-Aufwertung fein genug?

**Empfehlung: Nein — auf Zeilengranularität anheben (dieselbe Primitive wie
die Richtungskorrektur), und deterministisch aufgewertetes `confirmed` im
Katalog als solches auszeichnen.**

Begründung:

1. Das Sicherheitsnetz dahinter ist real: `confirmed` öffnet nur die Tür. Die
   Elevation verlangt zusätzlich eine finding-eigene, validierte Referenz
   (Rationale 20–240 Zeichen, max. 2 Refs, Evidence-Ownership, Adjacency,
   `to == origin`), ist auf +1 Rang und High gekappt und wird bei
   refuted/ambiguous Evidenz unterdrückt. Ein falsch-positives `confirmed`
   allein erzeugt keine falsche Severity.
2. Trotzdem ist die Dateigranularität an zwei Stellen falsch kalibriert:
   - **Inkonsistente Beweislast im selben Codepfad:** Die Richtungskorrektur
     (geringere Wirkung — sie dreht from/to) verlangt den Route-Match an der
     *zitierten Zeile* (`_looks_inbound` → `_evidence_line`); die
     Confidence-Aufwertung (größere Wirkung — sie schaltet den gesamten
     External-Ingress-Kanal frei) begnügt sich mit *irgendeinem* Match in den
     ersten 512 KB der Datei. Bei server.ts mit 172 Registrierungen ist das
     Kriterium praktisch immer erfüllt, unabhängig davon, ob die zitierte
     Stelle die behauptete Querung belegt.
   - **Semantik-Inflation eines sichtbaren Feldes:** `confirmed` ist im
     Agentfile als „only after inspecting relevant source/config evidence"
     definiert und steht so im gerenderten Katalog. Ein Regex-Match auf
     Dateiebene ersetzt dieses Urteil, ohne dass ein Leser den Unterschied
     sehen kann.
3. Konkret: `_ingress_is_evidenced` auf `_evidence_line` (±kleines Fenster,
   z. B. 3 Zeilen, für mehrzeilige Registrierungen) umstellen. Die
   routengranulare Ausbaustufe — Abgleich der zitierten Stelle gegen
   `.route-inventory.json`, das bereits existiert — ist möglich, aber nicht
   nötig, solange die Zeile selbst die Registrierung zeigen muss.
4. Unabhängig von der Granularität: die Aufwertung provenienzieren, z. B.
   `confidence_basis: route-evidence` (oder ein `sources`-Eintrag), damit
   analystisch bestätigtes und deterministisch aufgewertetes `confirmed`
   im Katalog unterscheidbar sind. Das ist auch die Voraussetzung dafür, die
   Aufwertung später enger oder weiter zu stellen, ohne Alt-Läufe
   fehlzuinterpretieren.

## F4 — Mischt das `kind`-Enum unvereinbare Taxonomien?

**Empfehlung: Ja, und die Zerlegung in zwei orthogonale Achsen lohnt sich —
gerade weil die Migration nachweislich billig ist. Alte Werte als
Eingabe-Aliase weiter akzeptieren.**

Begründung:

1. Die Diagnose stimmt: network/process beschreiben den **Mechanismus** der
   Querung, identity/privilege/tenant/data-origin beschreiben, **was sich
   ändert**, third-party/build beschreiben die **Betreiber-/Lebenszyklus-
   Domäne**. tb-3 (identity) ist zugleich eine Netzwerkquerung; tb-5
   (third-party) ebenso. Die Werte sind weder disjunkt noch parallel, und der
   Analyst muss bei jeder Mehrfachzutreffung eine undokumentierte
   Präzedenzentscheidung raten.
2. Die Migrationskosten sind klein, weil der Konsum zentralisiert ist: **jede**
   behaviorale Verzweigung auf kind liegt in `prepare_trust_boundary_context.py`
   (Focus-Tier, Dispatch-Ranking, Coercion, Re-Anchoring, Folding); Rendering,
   Triage, QA und Exporte reichen den String nur durch. Zwei Felder —
   `surface: network | in-process | build-pipeline` und
   `transition: [identity, privilege, tenant, data-origin, operator]`
   (Array, weil eine Querung mehrere Übergänge tragen kann; leer = reine
   Schnittstelle) — ersetzen das Enum, und die Focus-Tier-Logik liest dann
   `transition`-Mitgliedschaft statt kind-Mengen. Eine Datei, plus
   Schema-Bumps.
3. Deterministische Alt→Neu-Abbildung: network→(network, []),
   process→(in-process, []), identity→(network, [identity]),
   tenant→(network, [tenant]), data-origin→(network, [data-origin]),
   third-party→(network, [operator]), build→(build-pipeline, [operator]),
   privilege→(unverändert übernehmen, [privilege]) — mit `surface: network`
   als Default, wie es der bestehende Normalisierungs-Fallback (`:230`) heute
   schon tut.
4. Der teuerste Teil ist nicht der Code, sondern die **fremd-autorierte
   Eingabe**: `.appsec/trust-boundaries.yaml` (repo-declared,
   `schemas/trust-boundaries-repo.schema.yaml`) verwendet dasselbe Enum in
   Nutzer-Repos. Deshalb: das alte Enum als Eingabe-Alias unbegrenzt weiter
   akzeptieren und in der Normalisierung deterministisch mappen; nur die
   internen/kanonischen Artefakte tragen die zwei Achsen.
5. Nebeneffekt: F2 löst sich terminologisch (leere Transition-Achse macht
   „keine Trust-Transition" explizit renderbar), und die Focus-Tier-Regeln
   werden lesbar („hat Transition" statt Aufzählung von kind-Werten).

## F5 — `enforcement_point` als Pflichtfeld?

**Empfehlung: Nein — optional lassen. Stattdessen (a) generische Werte
deterministisch neutralisieren, (b) fehlende Werte in der Coverage-Diagnostik
sichtbar machen, (c) das Feld in den kanonischen Katalog durchreichen, statt
es bei der Promotion zu verwerfen.**

Begründung:

1. Vorab die Prämissenkorrektur (Abschnitt 0): die `--resume`-Begründung für
   die Optionalität existiert nicht; das Feld war von Einführung an optional,
   mit der dokumentierten Politik „Separation must be justified, not
   consolidation". Die Frage „Pflicht plus Migrationspfad?" adressiert damit
   eine Begründung, die der Code nicht gibt — die tatsächliche
   Design-Entscheidung ist bewusst und hat eine bessere Verteidigung als
   Artefakt-Kompatibilität.
2. **Schema-Pflicht erzwingt bei einem LLM Präsenz, nicht Qualität.** Der
   vorhersagbare Failure-Mode ist exakt der im Agentfile benannte: hand-waved
   Werte („application code", „Express middleware"). Und der ist hier nicht
   harmlos, sondern gefährlicher als Abwesenheit, denn der Point-Schlüssel
   enthält from/to nicht: derselbe generische String + gleiche crossing_class
   merged Kandidaten **über verschiedene Komponentenpaare hinweg** still zu
   einer Boundary. Abwesenheit degradiert dagegen in den konservativen,
   sichtbaren Crossing-Fallback. Die Code-Rationale selbst benennt die
   Asymmetrie: „over-merging destroys information silently, whereas
   under-merging stays visible … and is fixable next run." Ein Pflichtfeld
   würde den stillen, destruktiven Pfad zum Normalfall machen.
3. **Generik-Validierung: ja, aber nicht als Schema-Pattern.** Generizität ist
   lexikalisch nicht fassbar (ein `pattern` gegen „code" verbietet auch
   „authorization code exchange"). Richtig platziert ist sie als
   deterministische Normalisierung in der Promotion: eine kleine Denylist
   generischer Phrasen (application code, the application, middleware, server,
   nackte Framework-Namen) setzt den Wert auf None → Fallback-Pfad. Damit ist
   der gefährliche Fall (generischer String gruppiert komponentenübergreifend)
   konstruktiv unmöglich, und der Analyst wird für ehrliches Weglassen nicht
   bestraft.
4. **Sichtbarkeit statt Zwang:** `.trust-boundary-coverage.json` /
   `-diagnostics.json` existieren bereits als Gate-Artefakte; ein non-fatales
   Issue „N von M Kandidaten ohne enforcement_point" erzeugt den
   Verbesserungsdruck, den ein Pflichtfeld erzeugen soll, ohne dessen
   Failure-Mode.
5. **Das eigentliche Defizit ist die Write-only-Natur des Felds.** Es wird bei
   der Promotion verworfen (`:1535-1550`; kanonisches Schema kennt es nicht)
   — die Konsolidierungsentscheidung ist im fertigen Modell nicht auditierbar,
   und ein Folge-Lauf kann die frühere Gruppierung nicht aus
   `threat-model.yaml` rekonstruieren. `enforcement_point` in das kanonische
   Schema und den §1-Katalog aufnehmen (bei gemergten Boundaries der
   Survivor-Wert). Erst mit dieser Sichtbarkeit lässt sich ein späterer
   Pflicht-Schwenk überhaupt empirisch bewerten — nach ein paar Läufen mit dem
   neuen Analyst-Prompt sieht man, ob das Feld zuverlässig und spezifisch
   gesetzt wird. Heute gibt es dazu null Datenpunkte (der Beleg-Lauf lief vor
   der Einführung).

---

## Anhang: zentrale Code-Referenzen

| Gegenstand | Ort |
|---|---|
| Boundary-Definition („crossing/enforcement question, not a zone container") | `agents/appsec-trust-boundary-analyst.md:50-51`; `agents/phases/phase-group-architecture.md:1398-1400` |
| Konsolidierung, Schlüsselkonstruktion | `scripts/prepare_trust_boundary_context.py:1340-1347` |
| „Separation must be justified"-Rationale | `scripts/prepare_trust_boundary_context.py:1333-1339` |
| crossing_class | `scripts/prepare_trust_boundary_context.py:1267-1272` |
| Same-Deployable via Glob-Containment (Zonen abgelehnt) | `scripts/prepare_trust_boundary_context.py:1217-1238` |
| Richtungskorrektur (zeilengranular) | `scripts/prepare_trust_boundary_context.py:1303-1311, 1431-1443` |
| Confidence-Aufwertung (dateigranular, 512 KB) | `scripts/prepare_trust_boundary_context.py:1312-1320, 1387-1428` |
| Promotion, Feld-Kopierliste (enforcement_point fällt weg) | `scripts/prepare_trust_boundary_context.py:1535-1550` |
| Elevation-Eligibility (3 Konjunkte) | `scripts/triage_compute_ranking.py:591-626` |
| Elevation (+1, Cap High, nur effektive Severity) | `scripts/triage_compute_ranking.py:477-492` |
| boundary_refs-Validierungskette (fail-open) | `scripts/prepare_trust_boundary_context.py:1105-1180`; `scripts/merge_threats.py:341-379`; `scripts/build_threat_model_yaml.py:2145-2171` |
| STRIDE-Emissionsregel (nur confirmed) | `agents/appsec-stride-analyzer.md:151-157` |
| kind-Enum (8 Werte), enforcement_point optional | `schemas/fragments/trust-boundary-candidates.schema.json:32-81` |
| Kanonisches Schema ohne enforcement_point | `schemas/fragments/trust-boundaries.schema.json` |
| Repo-declared Schema (Nutzer-Eingabe, gleiches Enum) | `schemas/trust-boundaries-repo.schema.yaml` |
| kind-Konsumenten (alle in einer Datei) | `scripts/prepare_trust_boundary_context.py:230, 431, 648, 660, 676, 861-873, 981-983, 1326, 1331` |
| Lauf-Belege (19→6→6, Dispositionen, tb-Katalog, 0 Boundary-Elevations) | `/home/mrohr/juice-shop/docs/security/.trust-boundary-*.json`, `.triage-flags.json`, `threat-model.yaml:1569` |
