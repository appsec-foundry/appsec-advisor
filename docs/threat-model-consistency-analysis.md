# Konsistenz-Analyse: Reproduzierbarkeit der Threat-Model-Ergebnisse

> **Zweck dieses Dokuments.** Eine ausführliche Analyse, welche Änderungen am
> `appsec-plugin` nötig wären, damit ein zweiter Durchlauf auf demselben
> Repository-Stand zu einem *möglichst identischen* Threat Model führt – ohne
> dass der Agent das vorherige Ergebnis kennt oder einlesen darf.
>
> Dieses Dokument ist **reine Analyse** (keine Implementierung). Es ist als
> Diskussionsgrundlage für eine spätere Umsetzung gedacht und beschreibt
> Ursachen, Maßnahmen, Zielkonflikte und eine empfohlene Reihenfolge.

---

## 1. Problemstellung

Ein wiederholter Lauf von `/appsec-plugin:create-threat-model` auf demselben
Commit desselben Repositorys erzeugt heute signifikant unterschiedliche
Ergebnisse: andere Komponenten-Auswahl, andere Komponenten-Namen, teils
andere Threat-IDs, andere Ratings, andere Formulierungen. Für AppSec-Teams
bedeutet das: die Ergebnisse sind schwer vergleichbar, Trendbetrachtungen
(„ist der Security-Stand besser oder schlechter geworden?") werden unmöglich,
und Reviews werden immer wieder neu ausdiskutiert, obwohl sich am Code nichts
geändert hat.

Die anspruchsvollere Anforderung ist dabei: **der zweite Lauf darf den ersten
nicht kennen.** Incremental Mode und Checkpoint-Resume lösen dieses Problem
nicht, weil beide implizit den Zustand des vorigen Laufs einlesen. Hier geht es
um echte *From-Scratch-Reproduzierbarkeit*: zwei unabhängige, frische Läufe
müssen ohne Kenntnis voneinander dieselbe Ausgabe erzeugen.

### Was heißt hier „konsistent"?

Vollständige Bit-für-Bit-Gleichheit ist bei LLM-basierten Agenten weder
realistisch noch notwendig. Ein sinnvoller Zielwert hat drei Ebenen:

1. **Strukturgleich** – dieselbe Komponentenliste, dieselben Trust-Boundaries,
   dieselben Abschnitte, dieselben Diagramme (Knoten- und Kantenmenge).
2. **Threat-gleich** – dieselbe Menge an Threats, identifiziert über ein
   stabiles Schlüsselpaar (`component_id`, `CWE`, `evidence.file:line`),
   identische Ratings (Likelihood/Impact/Risk), identische Zuordnung zu
   Mitigations.
3. **Textähnlich** – Formulierungen, Reihenfolgen und Labels unterscheiden
   sich nur in kosmetischen Details; Diffs sind klein und gut lesbar.

Ziel der Änderungen ist Ebene 1 und 2 hart, Ebene 3 best-effort.

---

## 2. Quellen der Variabilität

Um konsistente Ergebnisse zu erreichen, muss man die Nicht-Determinismus-Quellen
kennen. Das Plugin hat zehn: einige stecken im LLM, viele im Agenten-Design.

### 2.1 Modell-Sampling

Sonnet und Opus laufen im Plugin mit Default-Sampling, d.h. es werden pro
Token Wahrscheinlichkeiten gezogen. Schon bei gleicher Eingabe liefert das
Modell unterschiedliche Formulierungen, unterschiedliche Reihenfolgen, teils
unterschiedliche Urteile. Die `Agent`-Tool-Schnittstelle im Plugin setzt heute
**kein `temperature: 0`**. Selbst mit temperature=0 ist die API nicht perfekt
deterministisch (Hardware-Batching, numerische Drift), aber die Streuung sinkt
erheblich.

### 2.2 Komponenten-Auswahl (größte Einzelquelle)

Phase 9 wählt die STRIDE-Komponenten heuristisch aus
(`phase-group-threats.md:11`):

> „Always include: Auth/identity, Authorization, components handling
> PII/payments, Admin panel, Public API gateway. For Moderate/Complex: each
> backend service, frontend SPA, queue consumers, CI/CD pipeline. Cap at
> `MAX_STRIDE_COMPONENTS`."

Diese Anweisung ist unterspezifiziert: *was* „handling PII" ist und *welches*
die „highest-risk component" beim `quick`-Cap von 3 ist, entscheidet der
Orchestrator vom Lauf zu Lauf unterschiedlich. Zwei Läufe auf demselben
Monorepo können z.B. einmal `payment-service` und einmal `order-service` als
„PII-tragend" auswählen. Ab hier läuft alles downstream auseinander –
unterschiedliche STRIDE-Analysen, unterschiedliche Threats, unterschiedliche
Ratings.

**Sub-Quelle:** auch die Komplexitätsklassifizierung (`simple/moderate/complex`)
ist LLM-Urteil, beeinflusst das Turn-Budget und damit, *wie tief* der
Analyzer liest – je nach Budget findet er andere Dateien.

### 2.3 Komponenten-Benennung und -IDs

Der Orchestrator vergibt `COMPONENT_ID` und `COMPONENT_NAME` frei in der
Dispatch-Prompt. Zwar gibt es in `phase-group-threats.md:62` bereits eine
Normalisierungsregel, aber die wird nur *innerhalb eines Laufs* angewandt
(„Unify: Auth Service / Auth Module → Auth Service"). Zwischen zwei Läufen
wird aus „Auth Service" mal „Authentication", mal „auth-svc", mal
„identity-service". Da Threats per `component_id` gemerged werden, bricht
schon daran die Vergleichbarkeit.

### 2.4 Datei-Auswahl durch Recon- und STRIDE-Analyzer

`appsec-stride-analyzer.md:79` sagt explizit:

> „Read broadly — the files that matter for STRIDE are often not the obvious
> entry points."

Genau diese „Read broadly"-Freiheit ist ein Jitter-Verstärker: welche
Middlewares, Serialisierer, Auth-Checks der Analyzer tatsächlich öffnet,
hängt vom LLM-Zufall und von der Reihenfolge ab, in der `Grep` Ergebnisse
zurückgibt (Ripgrep selbst ist deterministisch, aber die Auswahl aus den
Grep-Treffern ist es nicht). Die „targeted greps bei fehlender Evidenz"
(Zeilen 127-131) werden ebenfalls vom Modell formuliert – unterschiedliche
Queries treffen unterschiedliche Stellen.

### 2.5 Likelihood- und Impact-Rating

Die Rubrik in `appsec-stride-analyzer.md:133-141` gibt zwar eine fest
definierte Matrix Likelihood × Impact → Risk, aber die *Eingänge* der Matrix
sind weiterhin reine LLM-Urteile:

> „Likelihood: High/Medium/Low — based on exploitability and exposure"
> „Impact: Critical/High/Medium/Low — based on asset tier and compliance scope"

Ein fehlendes Rate-Limiting kann einmal „Medium likelihood" sein und einmal
„High", weil das Modell den Public-Exposure-Grad unterschiedlich einschätzt.
Das Risiko springt dann zwischen Medium und High.

### 2.6 Dedup- und Merge-Entscheidungen

`phase-group-threats.md:56` schreibt:

> „Deduplicate same root cause across components"

„Same root cause" ist Fuzzy-Matching durchs LLM. Zwei Läufe können
unterschiedlich dedupen: einmal werden „Missing input validation at
`/api/user`" und „No schema check at `/api/user`" zusammengeführt, im
nächsten Lauf bleiben sie getrennt. Ergebnis: unterschiedliche
Threat-Anzahlen und unterschiedliche `T-NNN`-Vergabe.

### 2.7 Coverage-Checks erzeugen neue „Gap-Threats"

`phase-group-threats.md:68-74` (OWASP-Top-10-Abdeckung, Business-Logic-Check,
OWASP-LLM-Top-10) lässt den Orchestrator fehlende Kategorien erkennen und
*dafür neue Threats erfinden*. Diese synthetischen Threats sind ohne
Code-Evidenz begründet und variieren zwischen Läufen am stärksten – sie sind
die hauptverantwortliche Quelle für „Warum sehe ich im zweiten Lauf Threat
T-037 plötzlich nicht mehr?".

### 2.8 CWE-/Requirement-/Blueprint-Matching

Die Zuordnung eines Threats zu einer CWE, zu einer Anforderung aus der
Requirements-YAML (`appsec-stride-analyzer.md:208-224`) und zu einem Blueprint
ist LLM-Relevance-Matching („select the single requirement whose `text` best
matches"). Semantisches Matching ist per Definition nicht deterministisch:
derselbe Threat kann mal gegen `AUTH-3`, mal gegen `AUTH-7` gematcht werden,
wenn beide Anforderungen ähnlich klingen.

### 2.9 ID-Vergabe und Sortierung

`phase-group-threats.md:58` sagt:

> „Assign global IDs: T-001, T-002, … (by risk descending). Architectural
> violation threats sort first within their risk tier."

„Risk-descending" ist ein stabiler *Sekundärschlüssel* (Critical > High > …),
aber innerhalb eines Risk-Tiers fehlt ein expliziter Tie-Breaker. Die
tatsächliche Reihenfolge hängt davon ab, in welcher Reihenfolge die parallel
laufenden STRIDE-Analyzer-Hintergrundprozesse *fertig werden*. Das ist von
Systemlast, Tool-Rate-Limits und Glück abhängig – ein klassischer
Reihenfolge-Jitter.

### 2.10 Mermaid-Diagramme

C4-Diagramme, Sequence-Diagramme und das Technology-Stack-Diagramm werden vom
Orchestrator frei formuliert. Die *Knotenmenge* sollte gleich sein
(strukturell abgeleitet), aber Labels, Kantenbeschriftungen
(„POST /login", „HTTPS"), Reihenfolge innerhalb eines Subgraphs und
Pink-Markierung betroffener Knoten variieren.

### 2.11 Zeitstempel und externe Inputs

- `analyzed_at` im STRIDE-JSON und `generated` im YAML sind Wall-Clock-
  Zeitstempel – machen Diffs zwischen Läufen unvermeidbar verrauscht.
- Der externe REST-Context (`config.json` → `rest_url`) kann zwischen zwei
  Läufen unterschiedliche Antworten liefern (andere Tickets, andere
  Known-Findings).
- Die Requirements-YAML wird per HTTP geladen (`requirements_yaml_url`) mit
  Cache-Fallback. Zwei Läufe können unterschiedliche Versionen sehen.
- `docs/known-threats.yaml` kann sich zwischen Läufen ändern.

### 2.12 QA-Reviewer als zweite Variabilitätsquelle

`appsec-qa-reviewer.md` läuft nach dem Orchestrator und bearbeitet die
Ausgabe in-place: linkifiziert Pfade, repariert Diagramme, entfernt
Placeholders, prüft Cross-Referenzen. Auch diese Transformationen sind
LLM-gesteuert und fügen ihre eigene kleine Jitter-Schicht hinzu (andere
Link-Formulierung, andere Reparatur einer kaputten Mermaid-Zeile).

---

## 3. Maßnahmen – nach Hebelwirkung geordnet

Die folgenden Maßnahmen sind in absteigender Wirkungsreihenfolge dargestellt.
Die ersten drei Blöcke adressieren zusammen geschätzt 80 % des Jitters. Alles
darunter ist „Fein-Tuning".

### 3.1 Deterministische Komponenten-Inventur (höchster Hebel)

**Problem gelöst:** 2.2, 2.3.

**Kernidee.** Die Komponentenliste darf keine LLM-Entscheidung mehr sein. Sie
muss mechanisch aus dem Repository ableitbar sein, und zwar so, dass zwei
Läufe auf demselben Commit garantiert dieselbe Liste erzeugen.

**Vorgehen.**
- Der `appsec-recon-scanner` schreibt eine neue Datei
  `$OUTPUT_DIR/.components.yaml` mit einer *deterministisch abgeleiteten*
  Komponentenliste. Die Ableitung basiert auf physischen Artefakten im
  Repository, nicht auf Urteil:
  - ein Verzeichnis zählt als Komponente, wenn es genau eines dieser Marker
    enthält: `Dockerfile`, `package.json`, `pyproject.toml`, `go.mod`,
    `pom.xml`, `Cargo.toml`, `Procfile`, `serverless.yml`, `main.tf`.
  - die `component_id` wird mechanisch abgeleitet aus dem relativen
    Verzeichnispfad: `kebab-case(path.replace('/', '-'))`. Beispiel:
    `services/auth/api` → `services-auth-api`.
  - `component_name` wird aus dem `name`-Feld der Manifest-Datei gelesen
    (package.json `name`, pyproject `[project].name`, …). Fallback: Title
    Case des Verzeichnisnamens.
  - die Liste wird alphabetisch nach `component_id` sortiert.
- Eine zweite, feste Regel mappt diese Rohkomponenten auf STRIDE-Rollen
  (auth, authz, public-api, frontend, ci-cd-pipeline, data-store, …) über
  Heuristiken, die als Entscheidungstabelle kodiert werden, nicht als
  Fließtext für das LLM. Beispielregeln:
  - „Verzeichnis enthält `passport`, `next-auth`, `oauth`, `keycloak` → Rolle
    `auth`"
  - „Verzeichnis enthält eine OpenAPI-Spec → Rolle `public-api`"
  - „Root enthält `.github/workflows/` → virtuelle Komponente
    `ci-cd-pipeline`"
- Das `MAX_STRIDE_COMPONENTS`-Cap wird dann nach einer festen Prioritätsliste
  angewandt (auth > authz > public-api > frontend > payment > ci-cd >
  andere, alphabetisch). Kein LLM entscheidet mehr, *welche* 5 aus 12.

**Effekt.** Damit ist die Komponentenauswahl, die Benennung und die
Cap-Reduktion vollständig deterministisch. Downstream stimmen
Komponenten-Count und -IDs zwischen Läufen immer.

**Kosten.** Ein kleines Python-Modul (vermutlich in
`plugin/scripts/components.py`), das der Recon-Scanner aufruft. Die
Phase-9-Dispatch-Schleife liest die Datei statt selbst zu entscheiden.

### 3.2 Evidence-gebundene Threat-Katalogisierung mit Triggern

**Problem gelöst:** 2.4, 2.6, 2.7 (größter Teil).

**Kernidee.** Threats werden nicht mehr frei vom Modell erfunden, sondern
aus einem *Katalog von Threat-Templates* aktiviert, deren Trigger
Grep-Patterns und Datei-Marker sind. Das Modell wird zum Zuordner, nicht
mehr zum Erfinder.

**Vorgehen.**
- Ein neuer, versionierter Threat-Katalog, z.B.
  `plugin/data/threat-catalog.yaml`. Jeder Eintrag hat:
  ```yaml
  - id: TPL-INJ-001
    stride: Tampering
    cwe: CWE-89
    title_template: "SQL injection possible in {endpoint}"
    trigger:
      any_of:
        - grep: "db\\.query\\([^,]*\\+"      # String-Konkatenation
        - grep: "raw\\(\\s*['\"]"            # .raw(" …
    negates:                                  # wenn vorhanden, Trigger ungültig
      - grep: "prepare|\\?.*\\?|parametri"
    likelihood_rule: "exposed_http_endpoint -> High, internal -> Medium"
    impact_rule:     "asset_tier == Tier1 -> Critical, else High"
    mitigation_title: "Parameterize all DB queries"
  ```
- Der STRIDE-Analyzer bekommt als Eingabe *nur* die Templates, deren
  Trigger in den Dateien seiner Komponente matchen. Er führt keine
  freie Suche mehr, sondern verifiziert jedes vorgeschlagene Template:
  - ist der Match echt (nicht in einem Kommentar/Testfile)?
  - gibt es im selben Pfad einen Negator, der die Vulnerability aushebelt?
  - welche konkrete `file:line` ist die beste Evidenz?
- Nur wenn die Verifikation positiv ausfällt, wird das Template zu einem
  echten Threat im Output. Likelihood und Impact werden aus den
  `*_rule`-Feldern *deterministisch* berechnet, nicht gewürfelt.

**Effekt.** Die Menge der Threats pro Lauf hängt nur noch vom Code ab, nicht
vom Modell-Mood. Ratings sind durch feste Regeln definiert. Deduplication
wird trivial: zwei Threats sind identisch, wenn `(template_id, component_id,
file:line)` gleich ist.

**Kosten.** Der Katalog muss initial befüllt und gepflegt werden (~50-100
Templates für sinnvolle Abdeckung). Threats außerhalb des Katalogs sind
zunächst blinde Flecken – das ist der zentrale Zielkonflikt (siehe §4.1).

### 3.3 Deterministische Rating-Matrix mit festen Eingängen

**Problem gelöst:** 2.5.

**Kernidee.** Likelihood und Impact dürfen nicht mehr „Modellgefühl" sein.
Sie werden aus *messbaren Eigenschaften* der Komponente und des Befunds
berechnet.

**Vorgehen.**

| Eingabe | Quelle | Beitrag |
|---|---|---|
| `exposure` | Komponenten-Rolle aus 3.1: `public-api`/`frontend` = external, `internal-svc` = internal, `ci-cd` = build-time | Likelihood-Basiswert |
| `auth_required` | Recon-Scan: Middleware-Check vorhanden? | +/- Likelihood |
| `asset_tier` | Recon-Scan: existiert `docs/business-context.md` mit Tier-Angabe? Sonst: Tier 2 (default) | Impact-Basiswert |
| `compliance_scope` | Recon-Scan: PCI/HIPAA/SOC2-Marker im Repo | Impact-Multiplikator |

Die Regeln werden als Entscheidungstabelle in
`plugin/data/rating-rules.yaml` abgelegt und vom STRIDE-Analyzer mechanisch
angewandt. Keine Freitext-Begründung mehr im Rating – die Begründung ergibt
sich aus den gematchten Regeln.

**Effekt.** Zwei Läufe ergeben exakt dasselbe Rating für denselben Befund.
Wenn sich ein Rating ändert, dann weil sich der Code/die Konfiguration
geändert hat – das ist dann sogar eine nützliche Information.

### 3.4 Deterministischer Merge mit stabilen Tie-Breakern

**Problem gelöst:** 2.6, 2.9.

**Kernidee.** Die Reihenfolge der Threats im finalen Register darf nicht von
Hintergrund-Prozess-Schedulung abhängen. Sie wird durch einen lexikografisch
vollständig definierten Sortierschlüssel erzwungen:

```
sort_key = (
  risk_order,             # Critical=0, High=1, Medium=2, Low=3
  stride_order,           # S=0, T=1, R=2, I=3, D=4, E=5
  component_id,           # alphabetisch
  cwe_id,                 # numerisch
  evidence_file,          # alphabetisch
  evidence_line,          # numerisch
  template_id,            # alphabetisch
)
```

Innerhalb der Merge-Schleife wird exakt nach diesem Schlüssel sortiert.
Globale `T-NNN`-IDs werden *nach* der Sortierung vergeben und sind damit
deterministisch. Keine „architectural violations sort first within their
risk tier"-Ausnahmen – Ausnahmen sind Tie-Break-Quellen.

Deduplication arbeitet auf demselben Schlüssel *ohne* `template_id`:
identische `(risk, stride, component, cwe, file, line)` werden zum
lexikografisch kleinsten Template-Eintrag zusammengeführt.

**Effekt.** Die Threat-IDs sind über Läufe hinweg stabil, solange sich der
Code nicht ändert. Ein Diff zwischen zwei Runs zeigt nur echte Verschiebungen.

### 3.5 Content-basierte Threat-IDs (Alternative zu 3.4)

**Problem gelöst:** dieselben wie 3.4, stärker.

Statt sequenzieller `T-001, T-002, …`-IDs können die IDs aus einem
deterministischen Hash des Sortierschlüssels erzeugt werden:

```
T-<base32(sha256(component|cwe|file|line)[0:6])>
```

Vorteil: selbst wenn ein neuer Threat hinzukommt, verändern sich die IDs
anderer Threats *nicht*. Das ist deutlich diff-freundlicher – heute würde
ein neuer Critical-Threat alle T-NNN-IDs verschieben.

Nachteil: IDs sind nicht mehr menschenfreundlich („T-001" vs. „T-4FQKZ9").
Kompromiss: beides anbieten, mit einer Mapping-Tabelle am Anfang von
Section 8. Ich würde das als Option V2 einplanen, nicht als Pflicht.

### 3.6 Eliminierung der synthetischen Coverage-Gap-Threats

**Problem gelöst:** 2.7.

**Kernidee.** Die OWASP-Top-10-Coverage-Prüfung darf keine neuen Threats
erzeugen. Sie darf nur *einen Report-Abschnitt* produzieren, der angibt,
welche Kategorien im aktuellen Threat-Register vertreten sind und welche
nicht.

**Vorgehen.**
- Ersatz des heutigen Coverage-Blocks durch eine Matrix:
  „A01 Broken Access Control – abgedeckt durch T-0A7, T-0B2; A03 Injection
  – nicht abgedeckt, keine Evidenz gefunden; …"
- Keine Threats mehr aus dem Nichts („Theoretical SSRF risk – no evidence").
- Falls das AppSec-Team echte Pflicht-Threats will (z.B. „immer einen
  generischen DoS-Threat auflisten"), werden diese als *explizite* Einträge
  in den Threat-Katalog (3.2) aufgenommen, mit einem immer-aktivierenden
  Trigger.

**Effekt.** Der größte Jitter-Verstärker ist weg. Das Threat-Register
enthält nur noch evidenzbasierte Threats.

### 3.7 Regelbasiertes Requirement- und Blueprint-Matching

**Problem gelöst:** 2.8.

**Kernidee.** Statt LLM-Relevance-Matching wird jedem Katalog-Template
(3.2) eine *explizite* Requirement-ID aus der Requirements-YAML zugeordnet,
und zwar in den Template-Metadaten:

```yaml
- id: TPL-INJ-001
  …
  maps_to:
    requirements: [IV-002, IV-005]
    blueprints:   [BP-DB-001#parameterized-queries]
```

Das Matching wird ein einfacher Lookup, kein semantischer Vergleich.
Voraussetzung: die Template-IDs und die Requirement-Taxonomie müssen
gepflegt werden. Wenn die Requirements-YAML sich ändert, muss der Katalog
nachgezogen werden.

**Fallback**, falls das zu aufwendig ist: statt semantischer Matchings
werden nur exakte Keyword-Matches erlaubt (case-insensitive,
whole-word). „SQL injection" im Threat-Titel + „SQL injection" im
Requirement-Text. Kein weiches Matching mehr.

### 3.8 Externe Inputs einfrieren

**Problem gelöst:** 2.11.

- **Externe Context-URL.** Einen neuen Modus einführen, in dem die Antwort
  bei Laufbeginn abgerufen, zu SHA-256 gehasht und neben dem Threat Model
  abgelegt wird (`$OUTPUT_DIR/.context-inputs.sha256`). Ein zweiter Lauf
  hasht die aktuelle Antwort und bricht ab/warnt, wenn der Hash sich
  geändert hat. So bleibt wenigstens transparent, *warum* sich etwas
  geändert hat.
- **Requirements-YAML.** Dasselbe. Zusätzlich: wenn ein reproduzierbarer
  Lauf gewünscht ist (`--reproducible`-Flag), muss eine konkrete
  Requirements-Version per Hash gepinnt werden. Heute ist das Verhalten
  „Cache oder Live" – beides ist zeitabhängig.
- **Known-Threats-YAML.** Denselben Hash-Mechanismus. Falls sich die Datei
  ändert, ist das ein echter Unterschied zwischen den Läufen und soll im
  Report sichtbar sein.

### 3.9 Commit-Pinning des Repos

**Problem gelöst:** Drift zwischen zwei Läufen, die auf demselben Branch
laufen, aber zu unterschiedlichen Zeiten (Arbeitsverzeichnis hat
uncommittete Änderungen).

Vor Phase 1:

```
COMMIT_SHA = git rev-parse HEAD
DIRTY      = git status --porcelain | grep -v '^?' | wc -l
```

Beides wird in `threat-model.md` und in die YAML-Meta geschrieben. Wenn
`DIRTY > 0` und `--reproducible` gesetzt ist, bricht der Lauf ab. Das ist
die einzige Garantie, dass beide Läufe dieselbe Eingabe sehen.

### 3.10 Temperature und Sampling

**Problem gelöst:** 2.1 (teilweise).

Wenn der `Agent`-Aufruf im Plugin ein `temperature`-Feld durchreichen kann
(ich habe das im Plugin-Code noch nicht verifiziert – müsste der Umsetzung
vorausgehen), wird für alle Agenten `temperature: 0` gesetzt. Das senkt die
Streuung erheblich. Für Claude gibt es derzeit kein öffentliches
`seed`-Feature, das deterministische Sampling garantieren würde; perfekter
Determinismus bleibt also API-seitig unerreichbar. Deshalb sind die
Maßnahmen in §3.1–3.7 wichtiger: sie kompensieren die fehlende
Modell-Determinismus-Garantie durch deterministische *Eingaben* und
*Regeln*.

### 3.11 Diagramme mechanisch generieren

**Problem gelöst:** 2.10.

Aus der `.components.yaml` (3.1) kann ein kleines Python-Skript die
C4-Diagramme als Mermaid-Text generieren, sortiert und mit festen Labels.
Der Orchestrator liest die Diagramme nur noch ein und bettet sie in die
Markdown-Datei ein. Die Sequence-Diagramme bleiben LLM-generiert (sie sind
schwieriger mechanisch abzuleiten), werden aber kanonisiert: jeder
Teilnehmer bekommt einen festen Namen aus der Komponenten-Liste, die
Message-Reihenfolge folgt einem festen Schema (Request → Auth → Validation
→ Business Logic → Response → Error).

Als erster Schritt reicht sogar: die Diagramm-Knoten werden verpflichtend
alphabetisch sortiert, und der Orchestrator wird angewiesen,
Kantenbeschriftungen aus dem Code (Route-String + HTTP-Methode) statt aus
Formulierungen zu ziehen.

### 3.12 Timestamps aus dem Threat Model entfernen oder normalisieren

**Problem gelöst:** 2.11 (Zeitstempel-Jitter in Diffs).

Der `analyzed_at`-Zeitstempel auf `.stride-*.json` wird für die
Reproduzierbarkeit nicht mehr gebraucht (er wird nur fürs Logging genutzt).
Vorschlag:
- In der finalen `threat-model.md` und `threat-model.yaml` werden
  Zeitstempel auf den Tag genau ausgegeben (`YYYY-MM-DD`, nicht
  `YYYY-MM-DDTHH:MM:SSZ`), optional mit Commit-SHA daneben.
- In den Intermediate-Dateien bleibt der volle Zeitstempel (für Debugging),
  wird aber vom Merge bewusst ignoriert.
- Wenn absolute Reproduzierbarkeit wichtig ist (`--reproducible`), wird der
  Zeitstempel durch den Commit-SHA aus 3.9 ersetzt: `Generated from commit
  a1b2c3d`.

### 3.13 QA-Reviewer konservativ machen

**Problem gelöst:** 2.12.

Der QA-Reviewer läuft heute als kreativer Fixer. Für Reproduzierbarkeit
sollte er nur noch idempotente, regelbasierte Operationen durchführen:
- Linkify bekannter Pfade (mechanische Regel: jeder Pfad-String gegen
  VS-Code-Link-Template ersetzen, wenn der Pfad existiert).
- Prüfen, ob jede `T-NNN`/`M-NNN`-Referenz einen Anker hat.
- Validieren, aber *nicht ändern*, wenn ein Mermaid-Diagramm kaputt ist –
  stattdessen einen Fehler werfen, damit die Ursache (Phase 3) gefixt wird.

Die heutigen heuristischen Fixes („ich erkenne, dass der Autor hier einen
Placeholder vergessen hat, und fülle ihn auf") sind Variabilitätsquellen und
verschleiern außerdem Bugs in der Generierung.

### 3.14 Reproducibility-Test-Harness (Messgröße)

**Problem gelöst:** Nicht gelöst, sondern gemessen.

Ohne Messung ist „ist jetzt reproduzierbar" nicht falsifizierbar. Vorschlag:

- Ein neues Test-Skript `scripts/reproducibility-check.sh` führt
  `create-threat-model` zweimal auf einem festen Referenz-Repo aus
  (z.B. einem Fixture unter `tests/fixtures/sample-repo/`), in zwei
  getrennten Output-Verzeichnissen.
- Die beiden Outputs werden per strukturellem Diff verglichen:
  - YAML: identische Komponenten-Liste, identische Threat-IDs, identische
    Ratings → hart geforderte Gleichheit, sonst Test-Fail.
  - Markdown: normalisiert (Zeitstempel, Whitespace, Emoji-Varianten) und
    per `difflib` verglichen; ab einem Schwellenwert (z.B. > 5 %
    Zeilen-Unterschied) schlägt der Test fehl.
- Dieses Skript läuft in CI gegen das Referenz-Repo. So wird
  Reproduzierbarkeit ein CI-Invariant und jede Regression fällt sofort auf.

---

## 4. Zielkonflikte

Keine der obigen Maßnahmen ist umsonst. Die drei wichtigsten Tradeoffs:

### 4.1 Deterministische Kataloge vs. Entdeckungskraft

Der Threat-Katalog (3.2) verschiebt das Plugin vom „kreativen Threat
Modeller" zum „Compliance-Checker". Alles, was nicht im Katalog steht, wird
vom zweiten Lauf sicher *nicht* gefunden – aber auch vom ersten nicht.
Ohne Katalog findet das LLM mal diesen, mal jenen nicht-offensichtlichen
Threat; mit Katalog findet es stabil dieselben.

Für AppSec-Teams ist „stabil dieselben" oft mehr wert als „manchmal ein
Treffer mehr": Stabilität macht Trendanalyse und Tickets-Tracking möglich.
Aber das Trade-off muss bewusst akzeptiert werden.

**Mitigation des Trade-offs.** Einen *zweiten*, klar getrennten Modus
einbauen: `--mode discover` (LLM-kreativ, nicht reproduzierbar) und
`--mode baseline` (Katalog-basiert, reproduzierbar). Teams können in
regelmäßigen Abständen einen Discover-Lauf machen, um den Katalog mit neu
gefundenen Threats anzureichern, und zwischen den Discover-Läufen
verlassen sie sich auf den Baseline-Modus.

### 4.2 Regelbasierte Ratings vs. Kontext-Sensitivität

Die feste Rating-Matrix (3.3) berücksichtigt keine Nuancen, die ein Mensch
(oder ein LLM) sähe („das SQL-Injection-Risiko ist gering, weil die Tabelle
nur eine Read-only-Audit-Log ist"). Das ist ein echter Qualitätsverlust.

**Mitigation.** Ein Feld `rating_override` pro Template erlauben, in dem der
Katalog-Maintainer einmalig eine Ausnahme kodiert. Die Override wirkt
deterministisch (sie ist Teil des Katalogs), aber sie erlaubt es, die
wichtigsten Kontext-Anpassungen einzupflegen.

### 4.3 Reproduzierbarkeit vs. Laufzeit/Kosten

Evidenz-getriebene Katalog-Ausführung kann die Anzahl der Grep-Calls
erhöhen (jedes Template bringt eigene Trigger mit). Umgekehrt fällt dafür
die „freie Exploration" weg, die heute die meisten Turns verbraucht.
Netto-Effekt ist vermutlich *weniger* Turns, aber das ist unsicher und
muss gemessen werden. Die Maßnahmen 3.1, 3.2 und 3.3 zusammen sollten die
Token-Kosten senken, nicht erhöhen – solange der Katalog nicht exzessiv
groß wird.

---

## 5. Empfohlene Umsetzungsreihenfolge

Die Maßnahmen haben unterschiedliche Risiken und können schrittweise
eingeführt werden. Vorschlag für eine Staffelung in vier Stufen:

**Stufe 1 — Billige Stabilisatoren (geringes Risiko, messbarer Effekt).**
- 3.4 Deterministischer Merge mit Tie-Breakern
- 3.9 Commit-Pinning
- 3.12 Zeitstempel-Normalisierung
- 3.14 Reproducibility-Test-Harness (als Messlatte zuerst!)

Diese vier Punkte sind klein und ohne semantische Risiken. Sie schaffen die
Infrastruktur, auf der man den Effekt aller weiteren Änderungen messen kann.

**Stufe 2 — Struktur-Determinismus (mittleres Risiko, hoher Effekt).**
- 3.1 Deterministische Komponenten-Inventur
- 3.11 Diagramme mechanisch generieren (Teil 1: Sortierung)
- 3.8 Externe Inputs hashen und im Report ausweisen

Ab hier sind Komponenten und Diagramme stabil. Der Test-Harness sollte
deutliche Verbesserungen zeigen.

**Stufe 3 — Threat-Determinismus (hohes Risiko, höchster Effekt).**
- 3.2 Threat-Katalog einführen – zunächst nur als *zusätzliche* Quelle
  parallel zum LLM, mit Opt-in per Flag.
- 3.3 Regelbasierte Rating-Matrix
- 3.6 Coverage-Gap-Threats durch Report-Matrix ersetzen
- 3.7 Requirement-Matching per Lookup

Diese Stufe verändert das Produkt-Verhalten spürbar. Der Rollout sollte
per Flag erfolgen, nicht als Default.

**Stufe 4 — Feinschliff.**
- 3.5 Content-basierte Threat-IDs (optional, zweiter Modus)
- 3.10 Temperature-Steuerung (sobald Agent-Tool das unterstützt)
- 3.13 QA-Reviewer auf rein mechanische Operationen reduzieren
- 3.11 Teil 2: komplette Mermaid-Generierung aus Daten

---

## 6. Was bewusst nicht versucht werden sollte

Einige naheliegende Ideen sind Sackgassen:

- **„Das alte Threat Model als Kontext für den neuen Lauf einspeisen."**
  Das widerspricht explizit der Anforderung und verschleiert außerdem
  Regressions. Incremental-Mode existiert aus gutem Grund als separater
  Modus – er ist *nicht* dasselbe wie Reproduzierbarkeit.
- **„Seed-Parameter an Claude durchreichen."** Gibt es aktuell nicht als
  öffentliches API-Feature. Jede Lösung, die darauf baut, ist spekulativ.
- **„Self-Consistency"-Voting (dreimal laufen, Mehrheitsvotum).** Das
  erhöht Kosten und Laufzeit linear und behebt keine der strukturellen
  Quellen (Komponentenauswahl, ID-Vergabe). Es ist ein Workaround, keine
  Lösung.
- **„Output nach jedem Lauf diffen und den Diff als Source of Truth
  nehmen."** Produziert Merge-Konflikte und macht die Ausgabe
  pfadabhängig. Nicht skalierbar.

---

## 7. Zusammenfassung

Reproduzierbarkeit entsteht nicht durch bessere LLM-Prompts, sondern durch
**deterministische Eingaben und regelbasierte Transformationen**. Der
Einfluss des Modells muss so weit wie möglich aus Entscheidungen
zurückgedrängt werden, die über Ergebnis-Struktur entscheiden: welche
Komponenten, welche Threats, welche Ratings, welche Reihenfolgen. Der
heutige Plugin-Aufbau lädt das Modell ein, genau diese Entscheidungen frei
zu treffen – an mindestens zehn verschiedenen Stellen.

Die größten Hebel, in dieser Reihenfolge, sind:

1. Komponentenauswahl mechanisch aus dem Repo ableiten (§3.1).
2. Threats aus einem Evidenz-getriggerten Katalog zusammensetzen (§3.2).
3. Ratings per fester Entscheidungstabelle vergeben (§3.3).
4. Merge- und ID-Vergabe per vollständig definiertem Sortierschlüssel
   (§3.4).

Alles andere sind sinnvolle Ergänzungen, aber diese vier Punkte schaffen
den Großteil der Stabilität. Der Zielkonflikt zu „kreativer Entdeckung"
(§4.1) sollte bewusst akzeptiert und über einen zweiten, expliziten
Discover-Modus aufgelöst werden. Ein CI-getriebener
Reproducibility-Check (§3.14) ist Voraussetzung für jede sinnvolle
Verbesserung – ohne ihn ist nicht messbar, ob die Maßnahmen wirken.

---

## Anhang A: Abgleich mit dem Code-Stand (2026-04-10)

Dieser Anhang gleicht die Annahmen aus §2 und §3 gegen den tatsächlichen
Quellcode des Plugins ab. Er wurde nach einer direkten Lesung der
relevanten Dateien erstellt und ersetzt die ursprünglichen
Zeilennummern-Referenzen, wo diese gedriftet sind.

### A.1 Zeilennummern-Drift in §2

Die folgenden Referenzen stimmen nicht mehr mit dem aktuellen Stand von
`plugin/agents/phases/phase-group-threats.md` überein (die Datei ist seit
Erstellung der Analyse gewachsen):

| Doc-Ref (§2) | Tatsächliche Position heute | Inhalt |
|---|---|---|
| `phase-group-threats.md:11` | **unverändert** (Zeile 11) | „Always include: Auth/identity…" |
| `phase-group-threats.md:56` | nun Zeile **59** | „Deduplicate same root cause…" |
| `phase-group-threats.md:58` | **unverändert** (Zeile 58) | „Assign global IDs…" (wurde inzwischen durch den Sort-Key-Patch ersetzt, siehe A.3) |
| `phase-group-threats.md:62` | nun Zeile **71** | „Normalize component names…" |
| `phase-group-threats.md:68-74` | nun Zeilen **73–83** | Coverage Checks A–C |

Die Referenzen in `appsec-stride-analyzer.md:79`, `:127-131`, `:133-141`
und `:208-224` sind unverändert gültig.

### A.2 Neue Non-Determinismus-Quellen seit Erstellung der Analyse

Die ursprüngliche Analyse kennt zehn Quellen (§2.1–2.12). Seit ihrer
Erstellung sind zwei weitere in `phase-group-threats.md` hinzugekommen,
die §2 fehlen:

**2.13 Systemic-Threat-Consolidation (neu).** `phase-group-threats.md`
Zeilen 60–68 führen eine verpflichtende Konsolidierungsregel ein: wenn
drei oder mehr Threats denselben „root cause" auf verschiedenen
Endpoints/Komponenten teilen, werden sie zu einem systemischen Eintrag
zusammengeführt (Beispiele: IDOR-Kette, raw-SQL-Pattern, ungeschützte
Management-Endpoints, Sanitizer-Bypass). Die Entscheidung „derselbe root
cause" ist weiterhin LLM-Urteil. Effekte:

- Die Threat-Anzahl kann zwischen zwei Läufen um mehrere Einträge
  springen, wenn das Modell einmal konsolidiert und einmal nicht.
- Der konsolidierte Eintrag übernimmt die höchste Severity der Gruppe –
  ein Lauf mit aggressiverer Konsolidierung kann dadurch eine
  Critical-Zählung „hochheben" oder senken.
- Die Regel ist an `architectural_violation` gekoppelt (diese werden
  typischerweise systemisch markiert) und greift damit ins
  Sort-Key-Feld 1 ein.

**Maßnahme.** Die Konsolidierungsentscheidung auf ein hartes Kriterium
reduzieren: „dieselbe CWE, dasselbe Pattern-Template aus dem Katalog,
≥ 3 Vorkommen". Solange der Katalog (§3.2) nicht existiert, ist diese
Regel eine der größten verbleibenden Jitter-Quellen oberhalb der
Sort-Reihenfolge.

**2.14 Priority-aware Risk für Requirement-Threats (neu, teilweise
positiv).** `phase-group-threats.md` Zeile 57 überschreibt die
Standard-L×I-Matrix für Threats aus Phase 8b: Architekturverstöße werden
um eine Stufe eskaliert, MUST-Requirements erhalten mindestens High.
Das ist **deterministisch**, solange die Requirement-Priorität
deterministisch zugeordnet ist – also eine Verbesserung, sobald §3.7
(regelbasiertes Requirement-Matching) umgesetzt wird. Ohne §3.7 verlagert
sie den Jitter nur: das Matching entscheidet, welches Threat eskaliert
wird.

### A.3 Bereits umgesetzt (Stand 2026-04-10)

Gegenüber §3 sind folgende Maßnahmen inzwischen teilweise umgesetzt:

- **§3.4 Sort-Key und Tie-Breaker — umgesetzt in Merge-Schritt 3.**
  `phase-group-threats.md` definiert nun einen vollständigen
  acht-stufigen Sortierschlüssel (`architectural_violation`, `risk`,
  `stride`, `component_id`, `cwe`, `evidence.file`, `evidence.line`,
  `title`) und weist T-NNN erst nach der Sortierung zu. Die
  Split-by-Severity-Sortierung in Section 8 referenziert denselben
  Schlüssel. **Nicht umgesetzt**: content-basierte Hash-IDs (§3.5)
  bleiben optional.

- **§3.10 Temperature — nicht umsetzbar auf heutiger Plugin-Ebene.** Der
  Test `tests/test_agent_definitions.py:18` definiert `REQUIRED_KEYS =
  ["name", "description", "tools", "model", "maxTurns"]`; Claude-Code-
  Agent-Frontmatter akzeptiert kein `temperature`-Feld, und das
  Agent-Tool reicht keinen Temperature-Parameter durch. Damit ist §3.10
  **blockiert auf Platform-Support** und gehört nicht in Stufe 4 der
  Umsetzungsreihenfolge, sondern in eine separate „wenn Claude Code das
  unterstützt"-Warteliste. Ersatzweise kann im Prompt um konservative,
  knappe Formulierungen gebeten werden – das reduziert Textstreuung,
  nicht aber Urteilsstreuung.

- **Assessment-Depth-Coverage-Skip (neu, positiv, nicht in §3 gelistet).**
  `phase-group-threats.md` Zeile 75 überspringt bei `quick`-Depth alle
  Coverage-Checks (§2.7) vollständig. Das ist effektiv eine Umsetzung
  von §3.6 für einen Laufmodus und macht `quick`-Läufe heute schon
  deutlich reproduzierbarer als `standard`/`thorough`. Für Teams, die
  Reproduzierbarkeit hart brauchen, ist `--assessment-depth quick` bis
  zur vollständigen Umsetzung von §3.6 die pragmatische
  Zwischenlösung.

- **Frontend-SPA-Override (neu, positiv).** `phase-group-threats.md`
  Zeile 13 erzwingt die Aufnahme einer Frontend-Komponente auf allen
  Depth-Levels, sobald der Recon-Scanner ein Frontend-Framework
  erkennt. Das eliminiert §2.2-Jitter für diesen Spezialfall.

### A.4 Konsequenzen für die Umsetzungsreihenfolge (§5)

Die Stufen-Staffelung aus §5 bleibt gültig, mit drei Änderungen:

- **Stufe 1**: §3.4 ist erledigt (Sort-Key + Tie-Breaker). Die
  verbleibenden Stufe-1-Punkte (§3.9 Commit-Pinning, §3.12 Zeitstempel,
  §3.14 Test-Harness) sollten vor allen anderen Maßnahmen angegangen
  werden – ohne Test-Harness ist die Wirkung des Sort-Key-Patches nicht
  messbar.
- **Stufe 4**: §3.10 Temperature wird aus der Liste gestrichen (nicht
  lösbar auf Plugin-Ebene). Stattdessen neu aufgenommen: **§3.15
  Systemic-Consolidation mechanisch machen** (aus A.2 oben) – diese
  neue Maßnahme gehört in Stufe 3, direkt nach §3.2 Threat-Katalog,
  weil sie ohne den Katalog kein hartes Kriterium hat.
- **Quick-Wins**: Bis §3.1 und §3.2 umgesetzt sind, sollte `--assessment-
  depth quick` als offizieller „Reproducibility-Modus" dokumentiert
  werden. Das ist keine Lösung, aber ein pragmatischer Workaround ohne
  Code-Änderung.

---

## Anhang B: Threat-Katalog — Schema-Skizze

Dieser Anhang konkretisiert §3.2 zu einem umsetzbaren YAML-Schema. Er
ist eine Design-Skizze, kein finales Schema – die Felder sind so
gewählt, dass die in §3.3 geforderte deterministische Rating-Berechnung
und das in §3.7 geforderte regelbasierte Requirement-Matching direkt
ableitbar werden.

### B.1 Dateilayout

```
plugin/data/
  threat-catalog.yaml          # Haupt-Katalog (versioniert)
  threat-catalog.schema.yaml   # JSON-Schema-Entsprechung zur Validierung
  rating-rules.yaml            # Entscheidungstabelle für Likelihood/Impact (§3.3)
```

Die Dateien werden zusammen mit dem Plugin ausgeliefert und über
`scripts/validate_catalog.py` bei jedem Release validiert. Der Katalog
trägt eine `schema_version` und eine `catalog_version`; beide werden
in den Ausgabe-Metadaten des Threat Models protokolliert, damit ein
Diff zweier Läufe den Katalog-Stand als Bedingung sichtbar macht.

### B.2 Top-Level-Struktur

```yaml
schema_version: 1
catalog_version: "2026.04.0"
last_updated: 2026-04-10
maintainer: "appsec-team@example.com"

# Gilt für den gesamten Katalog: wenn ein Template keine eigene
# Rating-Regel definiert, greift diese Default-Tabelle.
default_rating:
  exposure_to_likelihood:
    public_http:    High
    internal_http:  Medium
    build_time:     Low
    local_only:     Low
  asset_tier_to_impact:
    tier_1:         Critical
    tier_2:         High
    tier_3:         Medium
    tier_4:         Low

templates:
  - id: TPL-INJ-SQL-001
    # … siehe B.3
```

### B.3 Template-Eintrag (ein vollständiges Beispiel)

```yaml
- id: TPL-INJ-SQL-001
  version: 2                              # erhöht sich bei semantischer Änderung
  stride: Tampering
  cwe: CWE-89
  owasp_2021: A03
  title_template: "SQL injection in {component_name} — {endpoint}"
  description: >
    User-controlled input is concatenated into a SQL statement without
    parameterization. An attacker can inject arbitrary SQL clauses via
    the exposed endpoint and read, modify, or delete data beyond the
    current request's authorization scope.

  # ───── Trigger: wann aktiviert das Template? ─────
  # Die Trigger werden vom Recon-Scanner gegen die Komponenten-Dateien
  # gematcht. Matches sind mit file:line Evidenz zu unterlegen.
  trigger:
    applies_to_roles: [backend, public-api, internal-svc]
    any_of:
      - kind: grep
        pattern: 'db\.query\s*\(\s*["`][^"`]*\$\{'     # template literal + ${}
        file_glob: "**/*.{js,ts,py,go,rb,java}"
      - kind: grep
        pattern: 'execute\s*\(\s*["''][^"'']*\+ '       # string concat in execute()
        file_glob: "**/*.{js,ts,py,java}"
      - kind: grep
        pattern: '\.raw\s*\(\s*[\x27"]'                 # Knex/SQLAlchemy .raw("…")
        file_glob: "**/*.{js,ts,py}"
    negates:
      # Ein einziger Match hier macht den Trigger ungültig.
      - kind: grep
        pattern: 'prepare\s*\(|parameterize|[\$\?]\d+'
        scope: same_file
      - kind: file_exists
        path: "**/prisma/schema.prisma"                 # ORM mit Default-Escape
      - kind: dependency
        manifest: "package.json"
        name: "knex"
        version: ">=2.0"
        requires_pattern: "\\.raw\\("                   # ohne .raw(" ist Knex safe

  # ───── Rating: mechanisch berechnet ─────
  rating:
    likelihood_rule: default                            # use default_rating table
    impact_rule:
      base: tier_2
      if:
        - condition: "component.role == public-api"
          impact: Critical
        - condition: "compliance_scope contains PCI"
          impact: Critical
    architectural_violation: false

  # ───── Mapping zu Requirements und Blueprints ─────
  maps_to:
    requirements: [IV-002, IV-005]                      # exakte IDs, kein Matching
    blueprints:   [BP-DB-001#parameterized-queries]
    owasp_cheatsheet:
      url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"

  # ───── Fix ─────
  mitigation:
    title: "Parameterize all DB queries in {component_name}"
    effort: Low                                          # {Low, Medium, High}
    why: >
      Parameterized queries separate SQL code from data, preventing any
      user input from being interpreted as SQL syntax regardless of its
      content. This is the only complete defense against injection.
    how:
      - "Replace the concatenated query with a prepared statement using
         the driver's parameter API (`?`/`$1`/named parameters)."
      - "Bind every user-supplied value through the parameter list — do
         not inject identifiers via concatenation."
      - "Add a lint rule forbidding `.raw()` without an explicit allow-
         list comment."
    code_example_before: |
      db.query(`SELECT * FROM users WHERE email = '${email}'`)
    code_example_after: |
      db.query('SELECT * FROM users WHERE email = $1', [email])
    verification: >
      Send `' OR 1=1--` as the email field. The endpoint must return the
      same response as for any other non-matching email (no rows), not
      the full user list.

  # ───── Metadaten ─────
  tags: [injection, database, backend]
  first_seen_catalog_version: "2026.04.0"
  references:
    - "CWE-89"
    - "OWASP ASVS V5.3.4"
```

### B.4 Pflichtfelder und Validierung

Das Schema wird von `scripts/validate_catalog.py` gegen diese
Invarianten geprüft. Die Liste ist absichtlich knapp gehalten – jedes
zusätzliche Pflichtfeld erhöht die Pflegekosten.

| Feld | Pflicht | Regel |
|---|---|---|
| `id` | ja | Pattern `^TPL-[A-Z]+(-[A-Z0-9]+)+$`, global eindeutig |
| `version` | ja | Ganzzahl ≥ 1, monoton wachsend bei semantischen Änderungen |
| `stride` | ja | einer von `Spoofing/Tampering/Repudiation/InformationDisclosure/DenialOfService/ElevationOfPrivilege` |
| `cwe` | ja | Pattern `^CWE-\d+$` |
| `trigger.any_of` | ja | ≥ 1 Eintrag; jeder Trigger hat `kind` + passende Felder |
| `rating.likelihood_rule` | ja | `default` oder Regel-Objekt mit `base` + `if` |
| `rating.impact_rule` | ja | s.o. |
| `mitigation.title` | ja | nicht leer |
| `mitigation.verification` | ja | ≥ 10 Worte, keine Generics („verify the fix works") |
| `maps_to.requirements` | nein | wenn gesetzt: jede ID muss in der aktuellen requirements YAML existieren |
| `negates` | nein | verhindert False Positives — empfohlen bei allen grep-basierten Triggern |

### B.5 Wie der STRIDE-Analyzer den Katalog benutzt

Der Analyzer wird auf einen dünnen Verifier reduziert:

1. **Komponenten-Rolle laden** aus `.components.yaml` (§3.1).
2. **Kandidaten-Templates filtern** nach `trigger.applies_to_roles`.
3. **Für jedes Kandidaten-Template**:
   a. Jeden `any_of`-Trigger gegen die Komponenten-Dateien grep'en (alle
      Patterns stammen aus dem Katalog, keine LLM-Erfindung).
   b. Für jeden Match prüfen, ob ein `negates`-Trigger im gleichen Scope
      greift — falls ja, Match verwerfen.
   c. Für jeden übrig bleibenden Match: Datei lesen, bestätigen dass der
      Match kein Kommentar/Test ist, `file:line` festhalten.
4. **Rating mechanisch berechnen** aus `rating.likelihood_rule` und
   `rating.impact_rule` — kein Freitext-Urteil.
5. **Output schreiben**: ein Threat pro bestätigtem Match, mit
   `template_id`, `component_id`, `cwe`, `file:line`, und den
   mechanisch berechneten Ratings. Der Dedup-Schlüssel ist
   `(template_id, component_id, file, line)` — identische Tupel werden
   auf einen Eintrag reduziert.

Der Analyzer **erfindet keine Threats mehr**. Alles, was nicht im
Katalog steht, wird nicht gefunden – das ist der bewusst akzeptierte
Trade-off aus §4.1. Neue Threats wandern in separaten Discover-Läufen
in den Katalog und werden dann bei jedem Baseline-Lauf stabil geprüft.

### B.6 Beispiel: minimaler Katalog für einen Pilotlauf

Für einen ersten Pilotlauf reichen ~15 Templates, die die häufigsten
Befunde der bisherigen Läufe abdecken:

| Bereich | Template-IDs |
|---|---|
| Injection | `TPL-INJ-SQL-001`, `TPL-INJ-NOSQL-001`, `TPL-INJ-CMD-001` |
| AuthN | `TPL-AUTH-JWT-ALG-001`, `TPL-AUTH-HARDCODED-SECRET-001` |
| AuthZ | `TPL-AUTHZ-IDOR-001`, `TPL-AUTHZ-MISSING-GUARD-001` |
| Crypto | `TPL-CRYPTO-WEAK-HASH-001`, `TPL-CRYPTO-STATIC-IV-001` |
| Web | `TPL-WEB-XSS-REFLECTED-001`, `TPL-WEB-CSRF-001`, `TPL-WEB-OPEN-REDIRECT-001` |
| Supply chain | `TPL-SC-UNPINNED-ACTION-001`, `TPL-SC-UNPINNED-IMAGE-001` |
| Secrets | `TPL-SECRET-IN-REPO-001` |

Mit diesem Satz lässt sich gegen ein Referenz-Repo messen, ob der
Katalog-gestützte Modus mindestens dieselben Critical/High-Threats
findet wie der heutige LLM-Modus. Erst wenn diese Messung steht, wird
der Katalog produktionsreif ausgebaut.
