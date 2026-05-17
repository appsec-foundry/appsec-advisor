# Multi-Repo Threat Modeling — Analyse

Status: Konzept- und Designsondierung. **Nichts wird hier umgesetzt.**

Die Doc beantwortet die Frage: *Wie bezieht man Architektur-Eigenschaften und Bedrohungen sinnvoll über Repo-Grenzen hinweg ein, ohne ein zentrales Threat Model zu bauen — und was wird dadurch konkret sichtbar?*

---

## 1. Leitfrage und Antwort vorab

> Separate TMs pro Repo, oder ein zentrales TM über mehrere Repos mit Verweisen?

**Beides ist falsch als Alternative.** Die richtige Architektur hat drei Schichten:

1. **Security Charter / Org-Kontext** — langlebige, manuell gepflegte Inputs (Actors, Compliance, Business-Impact-Klassen, Severity-Maßstäbe)
2. **Repo Threat Models** — Source-of-Truth pro Repo, nah am Code (heute etabliert)
3. **Composed System View** — *abgeleitete* Cross-Repo-Sicht, jederzeit neu generierbar (heute nur als Findings-Roll-up vorhanden)

Ein hand-kuratiertes zentrales TM ist ein **Anti-Pattern** (Begründung in §3).

---

## 2. Stand der Bausteine (verifiziert gegen den Code, Mai 2026)

### Schicht 1 — Security Charter / Org-Kontext

| Baustein | Status | Bewertung |
|---|---|---|
| `schemas/org-profile.schema.yaml` | vorhanden | **Kein Charter.** Plugin-Config (Presets, Requirements-Source, Markdown-Kontext, skill_toggles, guardrails). Enthält *keine* Actors, Compliance-Maps oder Business-Impact-Klassen. |
| `org-profile.yaml > llm_context.documents[]` | vorhanden | Erlaubt Markdown-Anhang (z. B. `sso.md`, `platform.md`) — *prosaisch*, nicht strukturiert, kein maschinenlesbares Charter. |
| `schemas/known-threats.schema.yaml` | vorhanden | **Repo-lokal**, nicht org-weit. Hand-gepflegte Liste bekannter Threats des analysierten Repos. |
| Strukturiertes Charter (Actors, Compliance, Severity-Maßstäbe) | **fehlt** | Existiert weder als Schema noch als Datei. Diese Aspekte werden heute pro Repo *implizit* vom LLM erfunden — mit entsprechender Inkonsistenz. |

### Schicht 2 — Repo Threat Models

| Baustein | Status | Bewertung |
|---|---|---|
| `schemas/threat-model.output.schema.yaml` | vorhanden, reif | Source-of-Truth pro Repo, etabliert. |
| `components[]` | vorhanden | Felder: `id, name, description, paths, complexity, tier`. **Keine strukturierten `interfaces[]` mit stabilen IDs.** |
| `attack_surface[]` | vorhanden | `entry_point, protocol, auth_required, notes` — String-basiert, keine stabilen IDs. Heutiger Ort für Interface-Beschreibung. |
| `security_controls[]` | vorhanden | `domain, control, kind, implementation, effectiveness` — pro Komponente, nicht pro Interface. |
| `assets[]` | vorhanden | `name, classification` (Public/Internal/Confidential/Restricted). **Grobgranular**, kein Per-Feld-PII-Tagging. |
| `trust_boundaries[]` | vorhanden | `name, description`. Strukturiert, aber lokal pro Repo. |
| `data_flows[]` strukturiert | **fehlt** | Top-Level-Feld existiert nicht im Schema. Flows leben nur narrativ im Mermaid + Markdown. **Wichtige Konsequenz für §7.** |
| Actors strukturiert | **fehlt** | `grep actor` im Schema: leer. Actors leben nur narrativ im Report-Markdown / Mermaid. |
| `pentest-tasks.yaml > endpoints[]` | vorhanden | `id, path, source, auth, ...` — bereits Endpoint-Katalog pro Repo. **Nahe an einem Producer-Export**, müsste nur erweitert werden. |

### Schicht 3 — Composed System View

| Baustein | Status | Bewertung |
|---|---|---|
| `skills/generate-threat-overview/` + `scripts/aggregate_threat_summary.py` | vorhanden | **Findings-Roll-up**, keine Topology-Komposition. Aggregiert offene Threats über mehrere fertige TMs (shared-CWE, chain-candidates). |
| `schemas/threat-summary.schema.json` | vorhanden | Stabiler Output-Vertrag für Roll-up. |
| README-Selbstaussage | dokumentiert | *„Full cross-repo threat assessments are not supported yet. A single assessment that analyzes multiple repositories together is planned for a future release."* |
| Topology-Composition (Datenflüsse über Repo-Grenzen) | **fehlt** | Genau die Lücke, die User-Szenario adressiert. |

### Bestehende Cross-Repo-Mechanik (unabhängig von den Schichten)

| Baustein | Funktion |
|---|---|
| `schemas/related-repos.schema.yaml` | Deklaration upstream-Repos pro Repo (`name`, TM-Pfad/URL, `interface`, `components`, `auth_env`). |
| `scripts/load_related_repos.py` | Holt fremdes TM (lokal/HTTP), validiert, filtert nach interface + components, deckelt. |
| `scripts/build_cross_repo_register.py` | Merged declared + sibling-discovery + Recon Section 25 → `.cross-repo-register.json`. |
| `scripts/slice_cross_repo_for_component.py` | Per-Komponente, deterministisches Substring-Matching gegen name/description/interfaces/trust_boundaries. |
| `appsec-stride-analyzer` (`CROSS_REPO_CONTEXT_PATH`) | Konsumiert pro Komponente sliced Findings als *untrusted evidence*. |

**Was heute fließt:** ausschließlich *Findings* (open Critical/High) eines Upstream über die Trust-Boundary. *Keine* Architektur-Properties. *Keine* Datenfluss-Komposition.

---

## 3. Warum „ein zentrales TM über mehrere Repos" ein Anti-Pattern ist

Drei harte Gründe, einer reicht:

### Ownership-Vakuum
Niemand pflegt etwas, wofür niemand verantwortlich ist. Ein system-weites TM wird vom Architekten initial gebaut, dann veraltet es in Wochen. Häufigste Threat-Modeling-Pathologie überhaupt — keine Hypothese, sondern Beobachtung.

### Code-Anker brechen
appsec-advisor produziert Findings mit `file:line`-Evidence. In einem repo-übergreifenden TM müsste jede Evidence zu `repo+ref+file:line` werden. Ein Refactor in Repo A müsste das System-TM invalidieren. Mechanisch lösbar, aber gegen den Strich des Tools — und der Schema-Tradition (siehe `AGENTS.md` Core Rule 5: stabile IDs).

### Lifecycle-Mismatch
API-Repo released monatlich, Core-Repo wöchentlich. Welche Version steht im zentralen TM? Sobald man „Snapshot pro Repo" modelliert, baut man de facto eine schlechtere Variante von „Repo-TMs + Composition".

### Adoption
Repo-TMs adoptiert sich von selbst (`cd repo && /create-threat-model`). Ein zentrales TM braucht eine Org-Entscheidung, ein Owner-Modell, ein Pflege-Regiment. In der Realität: passiert nicht.

---

## 4. Was Repo-TMs strukturell *nicht* leisten können

Drei Aspekte, die nicht in ein einzelnes Repo gehören und deshalb heute redundant in jedem TM neu „erfunden" werden:

| Aspekt | Warum nicht repo-lokal | Wohin gehört es |
|---|---|---|
| Threat Actors | Systemisch, nicht repo-spezifisch („anonymous internet attacker" ist immer derselbe) | Schicht 1 (Charter) |
| Compliance-Anker (PCI-Scope, DSGVO-Kategorien, SOC2-Controls) | Geschäftsebene, nicht Code-Ebene | Schicht 1 (Charter) — Repo-TM markiert nur *welche* lokal relevant sind |
| Business-Impact-Klassen, Severity-Maßstäbe | Org-Eigenschaft | Schicht 1 (Charter) |
| End-to-End-Datenflüsse über Repo-Grenzen | Per Definition mehrrepoig | Schicht 3 (Composed View) |
| Cross-Repo-Threat-Paths („Anonymous → Frontend → API → DB") | Per Definition mehrrepoig | Schicht 3 (Composed View) |

Repo-TM behält:

- Lokale Komponenten + lokale Boundaries
- Code-spezifische Findings mit Evidence
- Repo-spezifische Mitigations
- Exposed/Consumed Interfaces (als Input für Komposition)

---

## 5. Verweise — wie sie aussehen sollten, wie nicht

„Andere Repos verweisen auf das zentrale TM" hört sich harmlos an, ist aber die Falle. Es gibt nur **zwei legitime Verweisformen**:

### Charter-Verweis (von oben)
Repo-TM referenziert Charter-IDs:

```yaml
applicable_actors: [charter/actors/anonymous-internet, charter/actors/insider]
compliance_scope: [charter/compliance/pci-dss, charter/compliance/gdpr]
```

Charter ist **Eingabe**, kein Knoten im Graph. Eine Datei für die ganze Org, gepflegt vom Sec-Team, low cadence.

### Interface-Verweis (horizontal, zwischen Repos)
Stabile Interface-IDs auf beiden Seiten:

```yaml
# core-repo: was ich konsumiere
consumed_interfaces:
  - interface_id: payments.v1.create
    called_from_component: checkout-handler

# api-repo: was ich anbiete
exposed_interfaces:
  - id: payments.v1.create
    transport: HTTPS
    auth: JWT
    output_pii: false
```

Der Composer joint diese zu einem verbundenen Datenfluss. Das ist **kein** Verweis auf das andere TM als Ganzes, sondern auf einen stabilen Identifier.

### Anti-Pattern: textuelle Verweise
Was du **nicht** willst: `siehe System-TM Section 4.2` in einem Repo-TM. Toter Link binnen Monaten, kein Schema-Vertrag, keine Validierung.

---

## 6. Designräume für Schicht 3 (Composition)

Sortiert nach Aufwand/Mehrwert. **Keine Empfehlung zur Umsetzung, nur Skizze.**

### Option A — Properties via Verweis (kleinster Schritt)
Erweitere `related-repos.yaml` um `import: [findings, data_flows]`. Loader extrahiert zusätzlich Datenflüsse, die die deklarierte Boundary kreuzen. STRIDE-Analyzer sieht *was* an Daten rüber geht, nicht nur *welche Findings* upstream offen sind.

Niedriges Trust-Risiko (Datenflüsse sind Beobachtungen, keine Sicherheitsbehauptungen). Aber: setzt voraus, dass Repo-TMs Datenflüsse strukturiert ablegen — was sie heute nicht tun (siehe §2). Vorarbeit nötig.

### Option B — Architecture Composition (der eigentliche Hebel)
Drei neue Bausteine:

1. **Producer-Export** (`export_architecture.py`): jedes Repo schreibt deterministisch `architecture-export.yaml` aus `route-inventory.json` + `architecture-coverage.json` + `pentest-tasks.yaml > endpoints[]` + `threat-model.yaml`. Inhalte: components, exposed_interfaces (mit stabilen IDs, Auth, Validation-Schema, PII-Tags, downstream sinks), boundaries.
2. **Consumer-Detection**: Recon-Erweiterung erkennt outbound HTTP/RPC-Calls als strukturierte `consumed_interfaces[]` (URL-Pattern, Method, source file:line, payload fields).
3. **Composer** (`compose_cross_repo_architecture.py`): joint per Drei-Tier-Matching (Tier 1: explizite ID, Tier 2: URL+Method, Tier 3: OpenAPI-Spec). Output: `cross-repo-architecture.json` mit `composed_flows[]` plus `unmatched_consumed[]` und `unmatched_exposed[]`.

STRIDE-Analyzer bekommt pro Komponente *first-class* Cross-Repo-Datenflüsse mit Producer-Properties. PII-Markierungen propagieren entlang des Flows.

### Option C — Invariant-Breakage-Detection (orthogonal, billig)
Beim Lauf Hash-Snapshot relevanter upstream-Items. Nächster Lauf vergleicht — Control verschwunden / Interface geändert / Severity gewachsen → auto-Hypothesis „Upstream-Annahme gebrochen". Lässt sich auf A oder B draufsetzen.

### Option D — Föderierter Graph (Overkill ohne Org-Katalog)
Jeder Repo exportiert SBOM-artige Security-Manifeste in ein zentrales Inventar. Aggregator baut Graphen. Nur sinnvoll, wenn Org-weiter Service existiert. Sonst Karteileiche.

### Option E — Hand-kuratiertes Contract-Layer (`provides`/`consumes`)
Eigene Datei `docs/security-contracts.yaml`, getrennt vom TM. Konzeptuell sauber, aber neue Pflege-Last pro Repo. Scheitert in der Praxis an Adoption.

---

## 7. Was die Composed View konkret liefert (Konkret-Analyse für den Use Case „Core + APIs")

Dieser Abschnitt beantwortet: *Was wird beobachtet, was wird gewonnen, ist der User-Use-Case abgedeckt?*

### 7.1 Zuständigkeitsgrenzen — drei Verantwortlichkeiten, getrennt

| Komponente | Art | Output | Vertrauensklasse |
|---|---|---|---|
| **Composer** | deterministisch, regelbasiert | `composed_flows[]` — Topologie, Properties, Sinks | Fakt (vorbehaltlich Matching-Qualität) |
| **Cross-Repo-Detector** *(optional, separater Schritt)* | deterministisch, regelbasiert | Findings wie „Auth-Mismatch", „Schema-Mismatch", „fehlende DiD an Boundary" | Regel-Aussage |
| **STRIDE-Analyzer** | LLM | Hypothesen mit Evidence, die `composed_flows[]` konsumieren | Hypothese — Provenance-Disziplin Pflicht |

Wichtig: die drei dürfen im Report **nicht vermischt** werden. Sonst kollabiert Trust-Boundary zwischen Beobachtung und Hypothese.

### 7.2 Sieben neue Beobachtungsklassen (B1–B7)

| # | Was wird beobachtet | Heute sichtbar? | Schema-Voraussetzung |
|---|---|---|---|
| B1 | **Verbundene Datenflüsse** Core.handler → API.endpoint | Nein, Flow endet am Repo-Rand | strukturierte `data_flows[]` pro Repo (heute fehlt!) + Interface-IDs |
| B2 | **Properties am anderen Ende** (Auth, Validation, Transport) | Nein, LLM rät | `exposed_interfaces[].auth/validation/transport` |
| B3 | **Downstream-Sinks** — was passiert NACH dem API-Call | Nein | `exposed_interfaces[].downstream_sinks` (komponenten-IDs des Producers) |
| B4 | **PII-Pfade end-to-end** mit Feld-Granularität | Nein, nur Asset-Klassifikation grob | Per-Feld-PII-Tag in Interface-Payload (heute fehlt!) |
| B5 | **Trust-Annahme-Brüche** Consumer-erwartet vs. Producer-liefert | Nein | `consumed_interfaces[].expects` + Composer-Vergleich |
| B6 | **Cross-Repo-Threats** durch Zusammenspiel | Nein | Cross-Repo-Detector mit Regelwerk (Auth-Mismatch etc.) |
| B7 | **Drift zwischen Läufen** | Nein | Snapshot-Hash über konsumierte Producer-Items |

**Ehrlicher Befund:** B1 und B4 brauchen erst Repo-lokale Schema-Erweiterungen, bevor Composition überhaupt darauf aufsetzen kann. Das macht Schicht 3 abhängig von vorausgehenden Schicht-2-Arbeiten.

### 7.3 Walkthrough — Core-Repo + zwei API-Repos

**Heute (Single-Repo, Core-Sicht):**

```
checkout-handler (Komponente)
  └── ruft externen Service: "payments API" (Beschreibung textuell)
       └── ENDE — was dort passiert, ist unbekannt
```

STRIDE-Hypothesen im Core: „creditCard wird über Netz übertragen — TLS prüfen, was sonst" — und dann hört die Analyse auf.

**Mit Composition (Cross-Repo-Sicht):**

Composer joint Core's `consumed_interfaces[]` mit beider API-Repos `exposed_interfaces[]`, ergibt `composed_flows[]`:

```yaml
composed_flow:
  source:
    repo: core-repo
    component: checkout-handler
    file: src/handlers/checkout.ts:42
    fields_sent: [creditCard, amount, customerId]
  destination:
    repo: payments-api
    component: payments-controller
    interface_id: payments.v1.create
    transport: HTTPS
    auth: JWT
    input_validation: schema:payment-create.v1
    output_pii: false
  downstream_sinks:                       # aus payments-api TM extrahiert
    - payments-db (PII-Store, encryption: at-rest)
    - audit-log (PII-Scrubbed)
  provenance: upstream-asserted
  freshness:
    producer_tm_generated: 2026-04-12T08:14:00Z
    consumer_run: 2026-05-17T09:00:00Z
    staleness_days: 35
```

Pro Cross-Repo-Call gibt es so einen Block. Plus `unmatched_consumed[]` für Calls ohne Producer-Treffer.

### 7.4 Emergente Cross-Repo-Threats — Beispiele

Threats, die *nur durch die Komposition* entstehen und in keinem einzelnen Repo-TM stehen können:

| # | Threat | Wie entsteht er |
|---|---|---|
| 1 | **Auth-Mechanismus-Mismatch** | Core hat Session-Cookie, API erwartet JWT — niemand transformiert. Detector findet das deterministisch via Property-Vergleich. |
| 2 | **Schema-Mismatch im Payload** | Core sendet `customerId`, API erwartet `accountId`. Detector sieht das ohne LLM. |
| 3 | **Trust-Vererbung durch kompromittierten Upstream** | Core vertraut API-Response blind. API hat Open-High SQL-Injection-Finding. Detector verbindet beide → „Antwort manipulierbar, Core ungeschützt". |
| 4 | **Fehlende DiD nach Behauptung „upstream validiert"** | API claimed `input_validation: schema:X`. Core revalidiert nicht. STRIDE-Hypothese: was, wenn upstream-Validation ausfällt? |
| 5 | **PII-Persistenz, die Consumer nicht erwartet** | Core sendet creditCard, API speichert in payments-db. Core-Team wusste nicht, dass Daten persistiert werden. Sichtbar via downstream_sinks. |
| 6 | **Identitäts-Transformations-Lücke** | Core hat User-Auth, ruft API mit Service-Account. API sieht nur Service-Account, kann keine User-Authorization mehr durchsetzen. |
| 7 | **Stale-Upstream-Annahme** | API hat letzte Woche `auth: JWT`, jetzt `auth: api-key`. Core's TM ist 35 Tage alt, Annahme veraltet. Snapshot-Diff findet das. |

Threats 1, 2, 7 sind **deterministisch** durch Cross-Repo-Detector erkennbar — keine LLM-Halluzination möglich. Threats 3, 4, 5, 6 sind STRIDE-Hypothesen auf Basis komponierter Topologie.

### 7.5 Use-Case-Coverage — explizit

User-Frage: *Core-Repo nutzt mehrere API-Repos, Datenflüsse verbinden — ist das abgedeckt?*

✅ **Vollständig abgedeckt** (vorausgesetzt Schicht-2-Vorarbeit ist erledigt):
- Verbindung Core → API über stabile Interface-IDs oder URL+Method-Matching
- Properties der API-Endpoints im Core-Report sichtbar (Auth, Validation, PII-Tags, downstream sinks)
- End-to-End-Datenflüsse mit PII-Propagation
- Cross-Repo-Threats durch Zusammenspiel (Auth-Mismatch, Schema-Mismatch, Trust-Vererbung)
- Drift-Detection wenn API sich ändert

⚠️ **Eingeschränkt abgedeckt:**
- **Matching-Lücke:** Tier-2 (URL+Method) trifft *vermutlich* 70–80% — Zahl ist Schätzung, nicht gemessen. Rest landet in `unmatched_consumed[]` (sichtbar als Bucket). Tier 1 (stabile IDs) braucht Adoption beider Teams.
- **Async-Flows** (Kafka, SQS, Event-Bus): konzeptuell analog, aber separater Schema-Block. Topic-Name als „Interface-ID", Producer-Subscriber-Relationen statt Caller-Callee. Heute nirgends modelliert.
- **Frische:** Composed View ist nur so aktuell wie der älteste beteiligte TM. Stale-Marker möglich (`staleness_days`), aber nicht reparierbar ohne Re-Scan.
- **Transitive Flows** (A → B → C): heutiger Entwurf ist 1-Hop. Graph-Walk über mehrere Hops technisch möglich, aber Schema-Komplexität wächst überproportional.

❌ **Nicht abgedeckt durch Composition (egal wie gebaut):**
- **Runtime-Verhalten** — was Services im Betrieb tun (Service-Mesh-Traces sind eine andere Quelle).
- **Tiefe Code-Findings im fremden Repo** ohne Producer-Scan — Composition zeigt Schnittstelle + dort offene Threats, geht aber nicht in den fremden Code für eine Live-CWE-Suche. Producer muss selbst gescannt sein (Source-of-Truth-Prinzip).
- **Multi-Hop-Identitätstransformationen** mit JWT-Exchange, Token-Forwarding, mTLS-Pinning über >2 Hops — modellierbar, aber jede Schicht erhöht Komplexität exponentiell. Realistisch: 2–3 Hops sauber.
- **Property-Konflikte zwischen Producern** — wenn zwei Repos widersprüchliche Aussagen über dieselbe geteilte Library oder Komponente exportieren, fehlt heute eine Konfliktauflösungs-Regel.

### 7.6 Was am Renderer-Bild gewonnen wird

Konkrete Effekte auf den Markdown-Report eines Composed-Laufs:

| Renderer-Element | Heute | Mit Composition |
|---|---|---|
| Mermaid-Diagramm | Repo-lokale Komponenten + textuelle „external" Box | Repo-übergreifende Subgraphs mit Cross-Repo-Pfeilen |
| §6 Attack Surface | Repo-Entry-Points | + Cross-Repo-Entry-Points (von welchen Consumern wird mein Endpoint aufgerufen) |
| §7 Trust-Boundaries | Repo-lokal | + Boundary-Übergänge mit Property-Übergangs-Tabelle |
| §7.X NEU: Cross-Repo Data Flows | nicht vorhanden | Tabelle: Source-Component → Destination-Component, Fields, Sinks, Provenance |
| §7.X NEU: Cross-Repo Threats | nicht vorhanden | Liste der emergenten Threats (Detector-Output) + STRIDE-Hypothesen |
| §11 Triage-Section | nur lokale Findings | + Cross-Repo-Findings mit klarem Provenance-Marker |
| `pentest-tasks.yaml > endpoints[]` | Repo-lokal | + `cross_repo_caller`-Annotation pro Endpoint |
| SARIF-Output | code-anker-basiert | unverändert — SARIF bleibt repo-lokal, weil Code-anker-basiert |

### 7.7 Ehrliche Caveats — Kosten, die in §6 zu billig dargestellt wurden

1. **`data_flows[]` strukturiert ablegen ist Voraussetzung, nicht Nebenarbeit.** Heute existiert das im TM-Schema nicht. Ohne strukturierte Flows pro Repo gibt es nichts zu komponieren. Das ist Schicht-2-Arbeit, nicht Schicht-3.
2. **Per-Feld-PII-Tagging ist Voraussetzung für B4.** Heute klassifiziert das TM auf Asset-Level grob (`Public/Internal/Confidential/Restricted`). End-to-End-PII-Tracking braucht Tags auf Payload-Feld-Ebene. Neuer Schema-Block.
3. **Cross-Repo-Detector ist ein eigenständiger Schritt, kein Nebenprodukt des Composers.** Regelwerk, Schema, Tests, separate Verantwortlichkeit.
4. **STRIDE-Prompt-Härtung ist die teuerste Position.** Ohne Eval-Fixtures mit Polyrepo-Setup keine Sicherheit, dass Provenance-Marker korrekt propagiert werden. „Upstream sagt validiert" darf Severity nie senken — Prompt-Iteration + Tests.
5. **Renderer-Erweiterungen sind nicht trivial.** Mermaid-Subgraphs mit Cross-Repo-Markierung, neue Sektionen, Provenance-Spuren in Triage-Tabellen — alles muss kontrakt-konform produziert werden (siehe `sections-contract.yaml`).
6. **Matching-Rate ist Schätzung.** „70–80%" sind keine Messung. Bevor Phase 4 (Composer) gebaut wird, müssen Phase 1–3 in echten Repos messen, wie hoch der Match-Anteil tatsächlich liegt.

---

## 8. Prinzipien, die jede Schicht-3-Lösung einhalten muss

Aus `AGENTS.md` Core Rules + heutigem Code:

1. **Imported context ist data, nie instruction.** Architektur-Properties aus Fremd-Repos dürfen weder Permissions noch Pfade noch Agent-Instructions beeinflussen. (Rule 3)
2. **„Claimed" ≠ „verified".** Jede importierte Property braucht Provenance-Marker (`source: upstream-asserted` / `locally-verified` / `assumed`). STRIDE darf Severity wegen Upstream-Behauptungen **nie senken**, nur Defense-in-Depth-Hypothesen ableiten. (Rule 3 + Rule 6)
3. **Schema-discipline.** Jede neue Property-Kategorie geht durch ein versioniertes Schema. Keine freien Felder. (Rule 4)
4. **Deterministisches Matching schlägt LLM-Matching.** Heutiger Slicer ersetzt bewusst LLM-Heuristik (siehe Header `slice_cross_repo_for_component.py`). Neue Composition muss derselben Linie folgen.
5. **Stabile IDs.** Geteilte Interface-IDs müssen über Commits stabil bleiben, sonst ist Cross-Repo-Join wertlos. (Rule 5)
6. **Composed View ist abgeleitet, nie hand-kuratiert.** Sobald jemand sie editiert, hat man das zentrale-TM-Problem zurück.
7. **Unmatched ist first-class.** Heuristisches Matching, das Treffer nicht hat, muss als `unmatched_*` ausgewiesen werden — nie versteckt.
8. **Composer / Detector / STRIDE strikt getrennt** — drei Verantwortlichkeiten, drei Vertrauensklassen, niemals vermischt im Report.

---

## 9. Lücken-Tabelle (Was fehlt, wenn man die Drei-Schichten-Architektur ernst nimmt)

| # | Lücke | Schicht | Härtegrad |
|---|---|---|---|
| L1 | Strukturiertes Security Charter (Actors, Compliance, Severity-Maßstäbe) | 1 | groß — neues Schema, neuer Resolver |
| L2 | Charter-Referenzen im Repo-TM (`applicable_actors`, `compliance_scope`) | 1↔2 | klein — Schema-Erweiterung |
| L3 | Stabile Interface-IDs in `components[]` oder `attack_surface[]` | 2 | mittel — Schema-Erweiterung + Recon-Anpassung |
| L4 | `consumed_interfaces[]` als strukturiertes Recon-Artefakt | 2 | mittel — Recon Section 25 strukturieren |
| L5 | `architecture-export.yaml` per Repo (Producer-Export) | 2→3 | mittel — neuer Script, neues Schema, kann auf `pentest-tasks > endpoints[]` aufsetzen |
| L6 | Topology-Composer (`compose_cross_repo_architecture.py`) | 3 | mittel — neuer Script, Drei-Tier-Matching |
| L7 | STRIDE-Prompt-Härtung für `composed_flows[]` mit Provenance | 3 | hoch — Prompt-Iteration, Eval-Fixtures |
| L8 | Invariant-Breakage-Detection (Snapshot-Diff über Läufe) | 3 | klein, aber wertvoll |
| L9 | Renderer für Cross-Repo-Mermaid + Cross-Repo-Section im Report | 3 | mittel — neue sections-contract-Einträge |
| L10 | Property-Import erweitern (`related-repos.yaml > import: [data_flows]`) | 2→3 alt-pfad | klein, schon nah am Vorhandenen |
| L11 | **Strukturierte `data_flows[]` im TM-Schema** (heute nur narrativ!) | 2 | **groß — Schema-Erweiterung, Phase-9/10b-Prompt, Renderer-Anpassung** |
| L12 | **Per-Feld-PII-Tagging in Interface-Payloads** (für B4 End-to-End-PII-Pfade) | 2 | mittel — Schema-Erweiterung + Recon |
| L13 | **Cross-Repo-Detector** als eigenständiger deterministischer Schritt | 3 | mittel — Regelwerk + Schema + Tests |
| L14 | **Konflikt-Auflösung** bei widersprüchlichen Producer-Aussagen | 3 | klein, aber Regel muss festgelegt werden |
| L15 | **Async-/Event-Flow-Modell** (Topics als Interface-IDs) | 2+3 | mittel — eigener Schema-Block |

L11 ist die wichtigste neue Erkenntnis aus §7: **Composition kann nicht starten, bevor Repo-TMs Datenflüsse strukturiert ablegen**. Heute tun sie das nicht.

---

## 10. Realistische Sequenz (falls jemals umgesetzt)

**Nicht** als monolithisches Projekt, sondern in der Reihenfolge des steigenden Werts. Jede Phase ist isoliert verifizierbar:

1. **L8 (Invariant-Breakage)** — ohne neuen Vertrag, ohne LLM-Risiko, billig. Funktioniert auf bestehender `related-repos.yaml`-Findings-Import-Strecke. **Realitätsprüfung:** Wer baut das, benutzt das nach drei Wochen noch? Wenn nein, Stop.
2. **L1 + L2 (Charter)** — Actors/Compliance-Konsistenz über alle Repo-TMs derselben Org. Kein Cross-Repo-Compute nötig.
3. **L11 (Strukturierte `data_flows[]` pro Repo)** — Pflicht-Vorarbeit für jede Composition. Eigenständiger Mehrwert: bessere Repo-lokale Threat-Modeling-Qualität, weil Datenflüsse explizit werden statt narrativ.
4. **L3 + L4 + L5 (Interface-IDs + Producer-Export + Consumer-Detection)** — Repo-lokale Artefakte, beide Seiten messbar einzeln. Datenqualität ohne L6 prüfbar (Anteil Routes ohne IDs, Anteil unmatched Calls).
5. **L12 (Per-Feld-PII-Tagging)** — optional, falls End-to-End-PII-Tracking gewünscht. Sonst überspringen.
6. **L6 + L13 (Composer + Cross-Repo-Detector)** — Topologie-Join + deterministische Cross-Repo-Findings. Beide ohne LLM.
7. **L7 + L9 (STRIDE-Integration + Renderer)** — die echte Cross-Repo-Sicht im Report. Nur sinnvoll, wenn 1–6 Datenqualität gezeigt haben.
8. **L14 + L15** — optionale Robustheit (Konfliktregeln) + async/event-Flows.

Nach Schritt 2 hat man bereits hohe Konsistenz über Repos hinweg, ohne irgendeine Composition. Nach Schritt 4 weiß man, ob Schritt 6+7 sinnvoll ist.

---

## 11. Offene Fragen vor jeder Umsetzung

- **Adoption-Realität:** Wieviele Repos haben heute `docs/related-repos.yaml`? Wieviele Einträge? Wenn die Antwort „nahe null" ist, ist die ganze Cross-Repo-Programmatik hypothetisch.
- **Charter-Owner:** Wer pflegt Schicht 1 in einer Org? Sec-Team einer reicht — aber wer ist es im konkreten Fall?
- **ID-Strategie:** Wie versioniert man geteilte Interface-IDs in Polyrepo-Welt ohne zentralen Katalog? Konvention pro Repo, oder Org-Konvention?
- **Konfliktauflösung:** Wenn zwei Upstreams widersprüchliche Properties über dieselbe geteilte Library oder denselben Endpoint melden — gewinnt der mit jüngerem TM, oder ist es ein Blocker?
- **Sibling-Auto-Discovery:** Heute metadata-only. Anheben auf Properties, oder bewusst out-of-scope lassen?
- **OpenAPI/AsyncAPI als Brücke:** Vorhandene Specs nutzen, statt eigene Interface-IDs erfinden? Trade-off: höhere Adoption, niedrigere Kontrolle über Property-Vokabular.
- **Eval-Setup:** Ohne Polyrepo-Fixtures + Eval-Cases ist STRIDE-Prompt-Härtung blind. Wer baut die Fixtures?
- **Granularität von `data_flows[]`:** Pro Komponente, pro Interface, pro Feld? Trade-off zwischen Schema-Komplexität und PII-Tracking-Genauigkeit.
- **Composed View — eigenes Dokument oder Section im Repo-TM?** Beim Repo-TM des Core ergänzen, oder separates `composed-system-view.md`? Erstere Variante integriert besser, zweite ist sauberer als „abgeleitete Sicht".
- **Async-Flows:** Eigenes Schema (`async_flows[]`) oder Erweiterung der `composed_flows[]` mit `transport: queue|event|sync`?
- **Transitive Composition (A→B→C):** Explizit 1-Hop, oder Graph-Walk? Letzteres ist mächtiger, aber Komplexität wächst überproportional.

---

## 12. Zusammenfassung in drei Sätzen

Separate Threat Models pro Repo sind die **richtige Wahl als Source-of-Truth** — sie leben mit dem Code, haben klare Owner, skalieren. Ein hand-kuratiertes zentrales TM ist ein Anti-Pattern, weil es Ownership-Vakuum, Lifecycle-Drift und Code-Anker-Bruch produziert. Was fehlt, ist **nicht** ein zentrales TM, sondern (a) eine **Charter-Schicht** über den Repo-TMs für die strukturell nicht-repo-lokalen Aspekte (Actors, Compliance, Severity-Maßstäbe), (b) **strukturierte Datenflüsse pro Repo** als Vorarbeit für Composition, und (c) eine **abgeleitete Composed View** unter den Repo-TMs für topologische Cross-Repo-Sicht (Datenflüsse, Threat-Paths, Property-Übergänge) — alle drei schemaversioniert, mit klarer Trust-Provenance, niemals hand-kuratiert auf System-Ebene.
