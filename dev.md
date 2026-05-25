# appsec-advisor — Wie das Plugin funktioniert

Dieser Text erklärt einem Außenstehenden, was das Plugin tut und wie es
intern arbeitet. Keine vollständige Referenz — eher eine Karte, damit man
sich im Code zurechtfindet.

---

## 1. Was macht das Plugin?

Du gibst in Claude Code den Befehl

```
/appsec-advisor:create-threat-model
```

ein, zeigst auf ein Code-Repository, und nach ein paar Minuten bekommst du
einen Sicherheitsbericht: welche Komponenten existieren, welche
Bedrohungen plausibel sind, was am wichtigsten ist, und Belege im Code für
jede Behauptung.

```mermaid
flowchart LR
  user["Du"]
  cc["Claude Code"]
  plugin["appsec-advisor"]
  repo[("Dein Repo")]
  out[("docs/security/")]

  user -- "/create-threat-model" --> cc
  cc -- "lädt Plugin" --> plugin
  plugin -- "liest Code" --> repo
  plugin -- "schreibt Bericht" --> out
```

Heraus kommen:

- `threat-model.md` — der lesbare Bericht für Menschen
- `threat-model.yaml` — dieselben Daten maschinenlesbar (für späteren
  Vergleich)
- optional `.sarif.json` und `.pdf`

### Auf einen Blick — die Pipeline für PO/Stakeholder

Was zwischen „Befehl drücken" und „fertiger Bericht" passiert, in
Alltagssprache. Jeder Block ist ein KI-Spezialist mit einer klaren
Teilaufgabe — wie ein kleines Review-Team, das nacheinander durch das Repo
geht.

```mermaid
flowchart LR
  classDef io fill:#eef,stroke:#558,color:#000,stroke-width:2px;
  classDef work fill:#fff,stroke:#666,color:#000;
  classDef check fill:#fff5e6,stroke:#cc8800,color:#000;
  classDef out fill:#efe,stroke:#383,color:#000,stroke-width:2px;

  In[("Dein Code-<br/>Repository")]:::io

  subgraph G1["1 · Verstehen"]
    direction TB
    V1["Repo lesen<br/><i>Sprache, Frameworks,<br/>Geschäftskontext</i>"]:::work
    V2["Komponenten finden<br/><i>Welche Bausteine?<br/>Wer vertraut wem?</i>"]:::work
    V1 --> V2
  end

  subgraph G2["2 · Bedrohungen denken"]
    direction TB
    B1["Pro Komponente:<br/>Was kann schiefgehen?"]:::work
    B2["Doppelte zusammenführen"]:::work
    B3["Belege im Code prüfen<br/><i>Stützt der Code<br/>die Behauptung?</i>"]:::work
    B1 --> B2 --> B3
  end

  subgraph G3["3 · Priorisieren & berichten"]
    direction TB
    P1["Wichtigkeit setzen<br/><i>P1 = jetzt fixen …<br/>P4 = später</i>"]:::work
    P2["Bericht schreiben<br/><i>lesbare Story<br/>+ Daten-YAML</i>"]:::work
    P1 --> P2
  end

  subgraph G4["4 · Qualitätsschleife"]
    direction TB
    Q1["Bericht selbst prüfen<br/><i>Tote Links? Lücken?<br/>Widersprüche?</i>"]:::check
    Q2["Architekt-Review<br/><i>(optional —<br/>zweite Meinung)</i>"]:::check
    Q1 --> Q2
  end

  Out[("Threat-Model<br/>für dein Team")]:::out

  In --> G1 --> G2 --> G3 --> G4 --> Out
```

Drei Dinge, die dabei wichtig sind:

- **Jeder Fund hat Code-Beleg.** Schritt „Belege prüfen" wirft alles raus,
  was nicht im Repo nachweisbar ist — keine erfundenen Bedrohungen.
- **Wichtigkeit, nicht Vollständigkeit.** Schritt 3 sortiert nach
  Behebungsreihenfolge. Das Team sieht sofort, was diese Woche dran ist.
- **Selbstkontrolle eingebaut.** Schritt 4 fängt typische KI-Schwächen
  (Halluzinationen, übersehene Platzhalter, Doppeleinträge) ab, bevor der
  Bericht ausgeliefert wird.

---

## 2. Drei Bausteinarten

Das Plugin ist aus drei Sorten Bausteinen gebaut. Es lohnt sich, diese
Trennung im Kopf zu haben — sie zieht sich durch das ganze Projekt.

| Baustein     | Wer denkt? | Beispiel                                        |
|--------------|-----------|-------------------------------------------------|
| **Skill**    | nur Regie | `create-threat-model` — der Einstieg            |
| **Agent**    | LLM       | `appsec-stride-analyzer` — sucht Bedrohungen    |
| **Script**   | Python    | `merge_threats.py` — dedupliziert Bedrohungen   |

Faustregel: **Python macht alles Mechanische, LLM macht alles, was
Interpretation erfordert.** Wann immer eine Aufgabe deterministisch
machbar ist (z.B. zwei Funde mit gleichem CWE zusammenführen, IDs
vergeben, Markdown zusammenkleben), übernimmt ein Python-Skript. Das spart
Geld und ist reproduzierbar.

---

## 3. Die Pipeline: vier Stages

Der Skill arbeitet in vier Schritten ab. Jeder Schritt hat ein klares Ziel
und endet mit einer Datei auf der Platte.

```mermaid
flowchart LR
  S0["Stage 0<br/>Vorbereitung"] --> S1["Stage 1<br/>Analyse"]
  S1 --> S2["Stage 2<br/>Bericht schreiben"]
  S2 --> S3["Stage 3<br/>Qualitätscheck"]
  S3 --> S4["Stage 4<br/>Architekt-Review<br/>(optional)"]
```

**Stage 0 — Vorbereitung.** Argumente einlesen, alte Lock-Dateien aus
abgebrochenen Läufen aufräumen, Konfiguration nach `.skill-config.json`
schreiben.

**Stage 1 — Analyse.** Hier passiert die eigentliche Arbeit: Code lesen,
Komponenten finden, Bedrohungen pro Komponente überlegen, Belege prüfen,
nach Wichtigkeit sortieren. Details in §4.

**Stage 2 — Bericht.** Aus den gesammelten Daten wird `threat-model.md`
gebaut. Ein eigener Agent füllt nur die Prosa-Abschnitte; alles andere
klebt ein Python-Skript zusammen.

**Stage 3 — Qualitätscheck.** Ein Reviewer-Agent (mit deterministischem
Python-Vorpass) prüft den fertigen Bericht: tote Links? Platzhalter
übersehen? Widerspricht der Text der YAML?

**Stage 4 — Architekt-Review (optional).** Ein zusätzlicher Reviewer
darf das Ergebnis kommentieren, aber nicht überschreiben. Er liefert nur
Empfehlungen.

### Welche Agenten laufen wann?

Die folgende Karte zeigt alle Agenten der Pipeline. Durchgezogene
Kästen laufen **immer**, gestrichelte nur unter bestimmten Bedingungen.

```mermaid
flowchart TB
  classDef always fill:#e8f0ff,stroke:#3355aa,color:#000,stroke-width:2px;
  classDef cond fill:#fff,stroke:#888,color:#555,stroke-dasharray:5 4;
  classDef optin fill:#fff5e6,stroke:#cc8800,color:#000,stroke-dasharray:5 4;

  subgraph S1["Stage 1 — Analyse"]
    direction TB
    CR["context-resolver<br/>liest Repo-Kontext"]:::always
    RS["recon-scanner<br/>findet Komponenten"]:::always
    CS["config-scanner<br/>nur wenn IaC vorhanden"]:::cond
    ST["stride-analyzer × N<br/>einer pro Komponente"]:::always
    TM["threat-merger<br/>nur wenn Duplikate gefunden"]:::cond
    EV["evidence-verifier<br/>prüft Code-Belege"]:::always
    TV["triage-validator<br/>setzt Prioritäten"]:::always
    CR --> RS
    RS --> CS
    CS --> ST
    ST --> TM
    TM --> EV
    EV --> TV
  end

  subgraph S2["Stage 2 — Bericht"]
    TR["threat-renderer<br/>schreibt Prosa-Abschnitte"]:::always
  end

  subgraph S3["Stage 3 — QA"]
    QA["qa-reviewer<br/>nur wenn Python-Vorpass Mängel meldet"]:::cond
  end

  subgraph S4["Stage 4 — Architekt (opt-in)"]
    AR["architect-reviewer<br/>nur mit --architect-review"]:::optin
  end

  S1 --> S2 --> S3 --> S4

  legend["<b>Legende</b><br/>━━ läuft immer<br/>┄┄ läuft bedingt<br/>┄┄ opt-in (User-Flag)"]
  class legend cond
```

Faustregel: **acht Agenten gehören zum Standard-Lauf**, einer ist nur bei
Bedarf dabei (`config-scanner`, wenn Dockerfiles oder Terraform existieren),
und der `architect-reviewer` läuft nur, wenn der User ihn explizit per Flag
anfordert.

---

## 4. Was in Stage 1 passiert

Stage 1 ist der Kern. Sie läuft in drei Blöcken ab:

```mermaid
flowchart TB
  R["Block A — Recon<br/>Was ist das überhaupt für ein Repo?"]
  A["Block B — Architektur<br/>Welche Komponenten gibt es?<br/>Welche Vertrauensgrenzen?"]
  T["Block C — Bedrohungen<br/>Was kann schiefgehen?"]
  R --> A --> T
```

### Block A: Recon

Drei kleine Agenten laufen **parallel**:

- `context-resolver` — liest README, package.json etc., schreibt eine
  kurze Beschreibung des Projekts
- `recon-scanner` — listet Manifeste, Routen, vorläufige Komponenten,
  bereits sichtbare Sicherheitsprobleme
- `config-scanner` — sucht Probleme in Dockerfiles, Terraform, IaC
  (nur wenn solche Dateien überhaupt vorhanden sind)

Parallel heißt: alle drei werden im gleichen Turn gestartet und im
Hintergrund ausgeführt. Der Orchestrator wartet auf alle drei, bevor es
weitergeht.

### Block B: Architektur

Hier baut der Orchestrator das Modell auf: welche Komponenten gibt es,
welche Daten fließen wohin, was sind die wichtigen Assets, wo verlaufen
Vertrauensgrenzen, welche Sicherheitskontrollen sind bereits vorhanden.
Das passiert in einer Reihe von Phasen, eine nach der anderen, derselbe
Agent.

### Block C: Bedrohungen

Der teuerste Teil. Für jede Komponente wird ein eigener
**STRIDE-Analyzer** gestartet — viele parallel.

```mermaid
flowchart LR
  O["Orchestrator"] -- "startet pro Komponente" --> S1["Analyzer für<br/>auth-service"]
  O --> S2["Analyzer für<br/>payment"]
  O --> S3["Analyzer für<br/>data-layer"]
  O --> Sn["..."]
  S1 --> F1[".stride-auth-service.json"]
  S2 --> F2[".stride-payment.json"]
  S3 --> F3[".stride-data-layer.json"]
```

Jede Instanz bekommt nur ihre eigene Komponente und nur den Ausschnitt
der Bedrohungs-Taxonomie, der dazu passt. Das hält die Aufgabe klein
und macht die Antworten besser.

Wieviele Komponenten überhaupt analysiert werden, hängt von der gewählten
Tiefe ab: `quick` = 3, `standard` = 5, `thorough` = 8.

### Danach: Aufräumen

Aus den N STRIDE-Dateien wird **ein** konsistenter Befund-Katalog:

1. **Sammeln** — ein Python-Skript gruppiert Kandidaten, die das gleiche
   CWE oder die gleiche STRIDE-Kategorie haben.
2. **Mergen** — ein LLM-Agent entscheidet pro Gruppe: gleiche Sache?
   zusammenfassen. Verwandt, aber unterschiedlich? getrennt lassen.
3. **Belege prüfen** — ein weiterer Agent liest die zitierten Code-Stellen
   nach und markiert jeden Befund als bestätigt, widerlegt oder unklar.
4. **Triage** — Schweregrad und Priorität festlegen.

Das Ergebnis ist eine Datei `.threats-merged.json` mit stabilen IDs.

---

## 5. Wie der Bericht geschrieben wird

Stage 2 ist absichtlich **schmal**. Der Renderer-Agent macht keine neue
Analyse — er liest nur die Daten aus Stage 1 und schreibt die paar
Prosa-Abschnitte (Zusammenfassung, Architekturbewertung). Ein
Python-Skript klebt dann alle Fragmente zu `threat-model.md` zusammen.

```mermaid
flowchart LR
  D[("Daten aus Stage 1")] --> R["Renderer<br/>schreibt Prosa"]
  R --> C["compose_threat_model.py<br/>baut die finale .md"]
  C --> G{"Hard-Gate<br/>Bericht okay?"}
  G -- ja --> S3["weiter zu Stage 3"]
  G -- nein --> X["Retry mit Reparatur-Plan<br/>(max 2×)"]
  X --> R
```

Wenn der Bericht nicht durchs Hard-Gate kommt (z.B. ein Abschnitt fehlt,
ein Platzhalter wurde nicht ersetzt), wird kein kaputter Bericht
gespeichert. Stattdessen wird ein strukturierter Reparatur-Plan
geschrieben und der Renderer noch einmal aufgerufen — gezielt nur für die
defekten Stellen.

**Eine harte Garantie:** Es landet niemals ein kaputtes `threat-model.md`
auf der Platte. Entweder der Bericht ist sauber, oder der Lauf endet mit
Exit-Code 2 plus Reparatur-Plan zum Drüberschauen.

---

## 6. Zweiter Lauf? Nur das Nötige

Wenn das Repo schon einmal analysiert wurde, kann der Skill mit
`--incremental` aufgerufen werden. Dann:

```mermaid
flowchart LR
  s["Start"] --> g["git diff seit letztem Lauf"]
  g --> rel{"sicherheits-<br/>relevante Änderungen?"}
  rel -- nein --> noop["Fast-Path: nichts tun"]
  rel -- ja --> dirty["nur betroffene<br/>Komponenten neu analysieren"]
  dirty --> carry["Rest unverändert<br/>übernehmen"]
```

Die alten Befunde behalten ihre IDs. Eine Komponente, die nicht angefasst
wurde, behält ihre Bedrohungen 1:1. Das hält Diffs zwischen Berichten
klein und macht es einfach zu sehen, was sich tatsächlich geändert hat.

---

## 7. Wo liegt was im Code?

Wenn du den Code anschauen willst, hier die wichtigsten Anlaufstellen:

| Was suchst du?                 | Wo schauen                                |
|--------------------------------|-------------------------------------------|
| Der User-Einstieg              | `skills/create-threat-model/SKILL.md`     |
| Wie die Pipeline orchestriert wird | `agents/appsec-threat-analyst.md`     |
| Die einzelnen Phasen           | `agents/phases/phase-group-*.md`          |
| Was die Worker-Agents tun      | `agents/appsec-*.md`                      |
| Deterministische Logik         | `scripts/*.py`                            |
| Bedrohungs-Wissen              | `data/cwe-taxonomy.yaml`, `data/threat-category-taxonomy.yaml` |
| Was darf in der YAML stehen?   | `schemas/threat-model.schema.json`        |

---

## 8. Begriffe in zwei Sätzen

- **Skill** — der Einstiegspunkt, den der User aufruft.
- **Orchestrator** — der eine Top-Level-Agent, der alle Phasen
  hintereinander abarbeitet (`appsec-threat-analyst`).
- **Sub-Agent** — ein vom Orchestrator gestarteter Worker mit eigenem
  Turn-Budget. Macht eine eng umrissene Aufgabe, schreibt eine Datei,
  kehrt zurück.
- **Phase** — ein nummerierter Arbeitsschritt innerhalb von Stage 1
  (Phase 1 = Recon, Phase 9 = STRIDE, Phase 10 = Mergen, …).
- **Fragment** — ein einzelner Markdown- oder JSON-Baustein, der später
  zum fertigen Bericht zusammengeklebt wird.
- **Hard-Gate** — der Schema-Check nach Stage 2; entscheidet, ob der
  Bericht durch darf oder repariert werden muss.
- **STRIDE** — das klassische Bedrohungs-Taxonomie-Schema (Spoofing,
  Tampering, Repudiation, Information Disclosure, DoS, Elevation of
  Privilege). Wird pro Komponente einmal durchgespielt.
