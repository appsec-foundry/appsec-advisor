# Design Decision: Templates und Schemas im appsec-plugin

**Status:** Teil 1 (`schemas/`) umgesetzt; Teil 2 (`templates/` — Fragment-Migration) zurückgestellt; Variante C (strukturierte Daten als Ground Truth) ausdrücklich aufgeschoben bis Produkttreiber vorliegen.
**Datum:** 2026-04-14
**Kontext:** Ausgelöst durch den Vergleich mit einem alternativen Multi-Agent-Threat-Modeling-Toolkit, das `schemas/`, `templates/`, `adapters/` und `brand/` als Top-Level-Verzeichnisse führt. Frage: Sind diese Konzepte auf das appsec-plugin übertragbar, und wenn ja, wie weit?

---

## 1. Ausgangslage

### 1.1 Aktuelle Pipeline

Das appsec-plugin dispatcht einen Orchestrator (`appsec-threat-analyst`) über 11 Phasen, der am Ende einen monolithischen Markdown-Report (`threat-model.md`) schreibt — angereichert durch YAML- und SARIF-Exporte. Datenartefakte zwischen den Agenten werden als JSON geschrieben:

- `.dep-scan.json` (vom `appsec-dep-scanner`)
- `.stride-<component-id>.json` (vom `appsec-stride-analyzer`, eine Datei pro Komponente)
- `.threats-merged.json` (vom Orchestrator in Phase 9 nach globaler T-NNN-Zuweisung)
- `.triage-flags.json` (vom `appsec-triage-validator` in Phase 10b)
- `threat-model.yaml` (finales externes Artefakt, strukturiert)

### 1.2 Was bereits existierte

- **Template-Infrastruktur vorhanden, aber im Embryonalstadium:** `plugin/templates/threat-model.template.md` enthielt einen einzigen Passthrough-Marker `{{include: 99-full-body.md}}`. Der dokumentierte Migrationsplan (14 Fragmente `00-*.md` bis `11-*.md`) war in `render_threat_model_schema.py` niedergeschrieben, aber nicht umgesetzt.
- **Schemas implizit in Python-Code:** `validate_intermediate.py` definierte die Contracts für `dep_scan`, `stride` und `threats_merged` als harte Feldlisten, Enum-Sets und Regex-Konstanten. Das finale `threat-model.yaml` hatte **keinen** Validator — der wichtigste externe Contract war ungesichert.

### 1.3 Welchen Ansatz das Referenz-Toolkit verfolgt

Das Vergleichs-Toolkit nutzt vier Top-Level-Ordner mit klar getrennter Verantwortung:

| Ordner | Zweck |
|---|---|
| `schemas/` | JSON/YAML-Contracts (finding.yaml, input.yaml, output.yaml, risk-scoring.yaml) als Single Source of Truth |
| `templates/` | Report-Fragmente (Markdown) + Typst-Templates für PDF-Rendering |
| `adapters/` | Portabilitätsschicht: STRIDE-Definitionen, MAESTRO-Mappings, die Agents referenzieren |
| `brand/` | Visuelle Identität für PDF/Infografiken |

Die architekturelle Konsequenz: Daten (von Agents produziert) und Darstellung (deterministischer Renderer konsumiert Templates) sind getrennt. Das ermöglicht PDF, Infografiken und Multi-Format-Output aus einer einzigen Datenquelle.

---

## 2. Betrachtete Optionen

Aus der Analyse ergaben sich drei grundlegende Varianten für das appsec-plugin:

### 2.1 Variante A — Fragment-Migration (dokumentierter MVP-Plan)

- Der Orchestrator schreibt statt eines Monolith-Body 14 separate Fragmente (`00-management-summary.md`, `08-threat-register.md`, …).
- Der bestehende Resolver inlined sie gemäß der `{{include: …}}`-Syntax.
- Layout bleibt vollständig LLM-generiert.

**Aufwand:** mittel. **Risiko:** gering. **Hebel:** Feingranulares QA/Retry pro Fragment.

### 2.2 Variante B — Templates mit Platzhaltern (Hybrid)

- Templates wie `08-threat-register.template.md` enthalten Platzhalter (`{{threats_table}}`, `{{badge_for(risk)}}`).
- Agenten produzieren strukturierte Daten, der Resolver substituiert.
- Prosa-Teile (Management Summary, Intros) bleiben LLM-generiert und werden in Templates eingebettet.

**Aufwand:** mittel-hoch. **Risiko:** mittel (LLM-Platzhalter-Disziplin brüchig). **Hebel:** deterministisches Tabellen-Layout, aber Hybrid-Zustand vereint Nachteile beider Welten.

### 2.3 Variante C — Vollständige Invertierung (datenzentriertes Modell)

- Agenten produzieren ausschließlich **strukturierte Daten** (YAML/JSON gemäß Schema).
- Ein deterministischer Python-Renderer erzeugt Markdown, YAML, SARIF, PDF, Infografiken aus denselben Daten.
- Narrative Teile (Management-Summary-Verdict, Section-Intros) werden entweder von einem dedizierten Narrative-Agent in YAML geschrieben oder aus Templates gezogen.

**Aufwand:** hoch (3–6 Wochen). **Risiko:** mittel-hoch in der Migrationsphase, niedrig danach. **Hebel:** sehr hoch — Multi-Format-Output, Re-Rendering alter Assessments, MCP-API, Testbarkeit.

---

## 3. Entscheidung

### 3.1 Die Entscheidung in einem Satz

**Zweistufiges Vorgehen, wobei nur die erste Stufe jetzt umgesetzt wird:**

1. **`schemas/` jetzt einführen** (Stufe 1, umgesetzt).
2. **Variante A, Variante B oder Variante C zurückstellen**, bis ein konkreter Produkttreiber (PDF, MCP-Server, Infografiken) die Investition rechtfertigt. **Keine Fragment-Migration als Selbstzweck.**

### 3.2 Warum Stufe 1 zuerst und alleine

Die drei Varianten für `templates/` haben eine gemeinsame Voraussetzung: **stabile Datencontracts**. Ohne sie ist jede Template-Arbeit brüchig, weil Template-Platzhalter oder Renderer-Eingaben gegen eine nicht-dokumentierte Form validieren. Schemas zuerst einzuführen ist darum nicht verhandelbar — unabhängig davon, welche Template-Variante später gewählt wird.

Darüber hinaus ist die Schema-Arbeit eigenständig wertvoll:

- `validate_intermediate.py` gewinnt deklarative Klarheit statt Python-Feldlisten.
- Das externe `threat-model.yaml` bekommt erstmals einen formalen Contract.
- Agent-Prompts können auf Schemas verweisen, statt Feldlisten zu duplizieren (künftige Prompt-Reduktion).
- CI kann Output-Drift vor Merge erkennen.

Die Schema-Umsetzung ist zudem **risikoarm**: Sie läuft additiv, der Public-API-Contract (`validate_dep_scan(data) -> (bool, errors)`) bleibt unverändert, alle 87 bestehenden Tests laufen weiter.

### 3.3 Warum Variante A nicht als nächster Schritt

Die Frage wurde explizit gestellt, ob Stufe 2 (Fragment-Migration, Variante A) als nächster Schritt sinnvoll sei. Die Antwort fiel negativ aus:

**Argumente dafür (schwach):**

- Die Template-Infrastruktur liegt seit Monaten halbfertig im Repo (`99-full-body.md`-Passthrough). Entweder abschließen oder bewusst aufgeben.
- Granulareres QA-Reviewing pro Fragment wäre möglich.
- Variante A bereitet grundsätzlich den Boden für Variante C.

**Argumente dagegen (stärker):**

1. **Niedriger Grenznutzen.** Das Layout bleibt LLM-generiert. Die versprochenen Hebel — Retry pro Fragment, Parallelisierung — sind theoretisch: der Orchestrator schreibt Fragmente in der Praxis sequenziell am Ende von Phase 11.
2. **Hoher Prompt-Engineering-Aufwand.** `appsec-threat-analyst.md` (1234 Zeilen) und die vier Phase-Group-Dateien (~2700 Zeilen) müssten umgeschrieben werden, damit sie statt eines Monoliten 14 getrennte Fragmente schreiben. Jeder Prompt-Umbau ist regressionsriskant.
3. **Fragmente-als-LLM-Output ist Zwischenetappe ohne eigenständigen Mehrwert.** Wer ohnehin auf Variante C zugeht, überspringt Variante A besser. Wer Variante C nicht will, bleibt bei heute.
4. **Instabile Ausgangslage.** Es gibt 13 pre-existierende Test-Failures zu Section 3/9-Prompt-Content — die Prompts sind gerade in Bewegung. Fragment-Migration obendrauf erhöht die Drift.
5. **Andere Arbeiten liefern höheren ROI:**
   - `threat-model.output.schema.yaml` in CI einhängen (direkter Regressionsschutz).
   - Produzierende Agenten auf Schema-Referenz umstellen (Prompt-Reduktion ohne Fragment-Umbau).
   - Pre-existierende Failures fixen (stabilisiert Section 3/9).
   - Zusatz-Features evaluieren (AI-Threats, Attack Chains) mit direktem Kundennutzen.

**Variante A ist die richtige Wahl nur, wenn** sich das Team definitiv gegen Variante C entschieden hat und die Template-Infrastruktur aus Hygiene-Gründen sauber abschließen will. Als reiner Feature-Treiber lohnt sich der Aufwand nicht.

### 3.4 Variante B ist ausgeschlossen

Die Hybrid-Variante (LLM-Prosa in Templates mit Platzhaltern) kombiniert die Nachteile beider Welten:

- LLMs halten Platzhalter-Disziplin nicht zuverlässig ein — Platzhalter werden „hilfreich" umformuliert oder dupliziert.
- Der Renderer muss dennoch defensiv gegen LLM-Varianz programmiert werden.
- Schema-Drift und Template-Drift treffen gleichzeitig.

Variante B wird als Sackgasse bewertet und nicht weiter verfolgt.

### 3.5 Variante C wird aufgeschoben, nicht verworfen

Variante C ist der strukturelle Endzustand, den die Architektur langfristig anstrebt — aber erst, wenn mindestens einer der folgenden Produkttreiber auf der Roadmap steht:

1. **PDF-Output.** Determistisches Rendering eines strukturierten Modells nach Typst/LaTeX ist ohne Variante C unmöglich.
2. **MCP-Server-Modus** (Roadmap-Item 1.0+). API-Konsumenten erwarten strukturierte Daten.
3. **Infografiken.** Baseball-Card, Funnel, Layer-Heatmap erfordern eine datenzentrierte Rendering-Pipeline.

Ohne mindestens einen dieser Treiber liefert Variante C **keinen ausreichenden Grenznutzen**, um die Umbaukosten (3–6 Wochen, mittel-hohes Migrationsrisiko) zu rechtfertigen.

---

## 4. Quantitative Einschätzung Variante C

Die Auswirkungen wurden vorab eingeschätzt, um die Größenordnung der späteren Entscheidung zu dokumentieren:

### 4.1 Tokens

- **Output-Tokens (Orchestrator):** –30 bis –45 %. Heute wird ein großer Teil der Output-Tokens für Layout-Plumbing verbraucht (Markdown-Tabellen-Pipes, HTML-Badges, VS-Code-Deeplinks, Cross-Reference-Anchors). Unter Variante C wird nur Datenstruktur geschrieben.
- **Input-Tokens (Agent-Prompts):** –10 bis –20 %. Layout-Anweisungen in Phase-Group-Dateien fallen weg; Agents referenzieren Schemas statt Feldlisten zu duplizieren.
- **Netto über alle Agenten:** –25 bis –35 % pro `standard`-Assessment. Der größte Hebel entsteht im `thorough`-Modus, wo Reports am längsten werden.

### 4.2 Laufzeit

- **Phase 11 (Finalization):** –50 bis –70 %. Heute dominiert das sequenzielle Markdown-Schreiben des Orchestrators die Phase. Unter Variante C schreibt der Orchestrator eine strukturierte Datei; der Renderer läuft lokal in <1 Sekunde.
- **Gesamt-Laufzeit:** –10 bis –15 % pro Run.
- **Parallelisierung:** MD, YAML, SARIF und PDF können aus derselben Datenbasis parallel gerendert werden — heute sequenziell und teilweise gar nicht vorhanden.
- **Retry-Geschwindigkeit:** Schema-Invalid-Outputs werden sofort durch Validierung erkannt; Retries betreffen nur strukturierte Daten, nicht volles LLM-Rendering.

### 4.3 Qualität

**Besser wird:**

- **Layout-Konsistenz:** Keine LLM-Renderer-Drift mehr (heute variieren Tabellen-Alignment, Leerzeilen, Badge-Formatierung zwischen Runs).
- **Cross-References:** T-NNN-Anchors deterministisch konsistent (heute via QA-Reviewer-Nachtrag geflickt).
- **Mermaid-Syntax:** Immer wohlgeformt (heute QA-Reviewer-Check mit 11 Regeln).
- **Testbarkeit:** Renderer kann isoliert gegen Fixtures getestet werden; Regressions-Tests werden deterministisch.
- **Re-Rendering alter Assessments:** Alte YAML + neuer Renderer = neuer Report ohne erneute Analyse. Heute undenkbar.
- **QA-Reviewer-Scope:** ~60 % der 10 Checks werden strukturell unnötig (Deeplinks, Badges, Cross-Refs, Anchors, Mermaid-Syntax, Section-Completeness).
- **Feature-Parität mit reiferen Toolkits:** PDF, Infografiken, MCP von „Monaten Arbeit" zu „Tagen Arbeit".

**Schlechter oder riskanter wird:**

- **Narrative Qualität:** Section-Intros und Management-Summary-Narratives entstehen heute im Fluss der LLM-Analyse. Ein separater Narrative-Agent, der nach der Analyse über strukturierte Daten schreibt, kann Kontextverdichtung verlieren. Gegenmittel: Narrative-Agent bekommt vollen Kontext — kostet Tokens.
- **Ausdrucksflexibilität:** Heute kann ein Agent ad-hoc eine Info-Box in eine Tabelle schreiben. Unter C muss jedes Feld im Schema existieren — Schema-Governance-Overhead steigt.
- **Migrationsrisiko:** Während des Umbaus ist Output-Qualität instabil. Parallelbetrieb alter/neuer Renderer via Feature-Flag empfohlen.

### 4.4 Saldo

Der Gesamteindruck der Reports würde unter Variante C **steigen**, weil Drift- und Layout-Probleme der dominante Qualitätsmangel heute sind — nicht die Prosa-Qualität. Aber nur, wenn der einmalige Umbauaufwand tragbar ist.

---

## 5. Umgesetzter Stand (Stufe 1)

### 5.1 Neue Artefakte

Unter `plugin/schemas/`:

- `README.md` — Contract-Dokumentation, Versionierungsregeln, Liste der Python-Post-Checks für nicht-ausdrückbare Invarianten.
- `dep-scan.schema.yaml` — JSONSchema für `.dep-scan.json`. Error-Stubs via `if/then/else` diskriminiert.
- `stride.schema.yaml` — JSONSchema für `.stride-<component-id>.json`. Gleiches Muster.
- `threats-merged.schema.yaml` — JSONSchema für `.threats-merged.json`. Sequenz-Prüfung bleibt in Python (Draft-2020-12 kann sie nicht ausdrücken).
- `threat-model.output.schema.yaml` — **neuer Contract**, der bisher fehlte. Deckt 10 Top-Level-Sektionen ab: `meta`, `changelog`, `components`, `assets`, `attack_surface`, `trust_boundaries`, `security_controls`, `threats`, `mitigations`, `critical_findings`, plus optionale Blöcke `run_statistics` und `cross_repo_dependencies`.

### 5.2 Refactor

- `plugin/scripts/validate_intermediate.py` lädt YAML-Schemas via `pyyaml` und validiert strukturell via `jsonschema` (Draft 2020-12). Python-Post-Checks bleiben für:
  - Sequenzielle T-NNN-IDs in `threats-merged`
  - Snippet-Redaktionsregel (`****` erforderlich, max. 4 Pre-Redaction-Chars)
  - Stripped-Length ≥ 10 Chars bei `scenario`
  - Blank-Title-Check bei Merged Threats
- Public-API (`validate_dep_scan(data) -> (bool, list[str])`) und CLI-Contract unverändert.
- `tests/requirements-test.txt` um `jsonschema>=4.20` ergänzt.

### 5.3 Neue Tests (`tests/test_schemas.py`)

- Jede Schema-Datei ist gültige Draft-2020-12 JSONSchema (`check_schema`).
- Das reale `docs/security/threat-model.yaml` validiert gegen `threat-model.output.schema.yaml` (Regression-Schutz gegen Output-Drift).

### 5.4 Testergebnis

93 Schema-Tests grün. Die 13 pre-existierenden Failures in `tests/test_incremental_mode.py` (Section-3/9-Prompt-Content) sind unverändert und unabhängig von dieser Entscheidung.

---

## 6. Ergänzende Entscheidung: Distribution

Während der Analyse kam die Frage auf, ob ein `install.sh`-Ansatz (Dateien werden pro Zielrepo kopiert) dem Plugin-Ansatz (`claude --plugin-dir` lädt zentral) überlegen wäre.

### 6.1 Vergleich

| Dimension | Plugin (wir) | Copy-in-repo (install.sh) |
|---|---|---|
| Update-Verteilung | Zentral — ein Update wirkt überall | Pro Repo manuell |
| Projekt-Fußabdruck | Zielrepo bleibt sauber (nur `docs/security/`) | Agent-/Template-Dateien landen im Git |
| Projektspezifische Anpassung | Via Config, kein Edit direkt im Repo | Lokale Edits committable |
| CI/CD-Einbindung | Einmal-Install am Runner | Jede Pipeline installiert neu |
| Versionspinning | Runner-weit | Pro-Repo nativ via `--version` |
| Template-Customization | Nur via Fork | Direkt editierbar |
| Langzeit-Wartbarkeit | Kein Skew | Skew garantiert |
| Air-Gapped | Plugin-Pfad muss erreichbar sein | Copy-and-run autark |

### 6.2 Bewertung

Für das erklärte Ziel des Plugins — **zentrales AppSec-Team-Tooling, das fremde Repos analysiert** — ist der Plugin-Ansatz klar überlegen. Das Copy-in-repo-Modell passt zu einer anderen Produktvision (Projekt-Framework zur Adoption durch Dev-Teams), die wir nicht verfolgen.

### 6.3 Hybrid-Option offen

Ein zusätzliches `install.sh`-Skript, das das Plugin optional als Projekt-Scaffolding in ein Zielrepo kopiert, ist als Option dokumentiert. Aufwand: 1–2 Tage. Nutzen: zweiter Adoptionskanal für Dev-Teams ohne zentrales Plugin-Deployment oder für Air-Gapped-Umgebungen. **Nicht jetzt umgesetzt**, da kein Bedarf artikuliert. Kann jederzeit additiv ergänzt werden, ohne den Plugin-Pfad zu ändern.

---

## 7. Konsequenzen und offene Punkte

### 7.1 Direkte Folgen der umgesetzten Schema-Stufe

- Schema-Drift im `threat-model.yaml` wird bei Tests als Failure sichtbar. Erste echte Regressionssicherung für das externe Artefakt.
- `validate_intermediate.py` ist deutlich kleiner und deklarativer; neue Felder erfordern nur Schema-Änderung, nicht Python-Änderung.
- Die Schema-Dateien werden zur primären Referenz für künftige Änderungen an Datenform. Produzierende Agent-Prompts sollten in Folgearbeiten auf Schema-Referenz umgestellt werden (Prompt-Reduktion ohne strukturellen Umbau).

### 7.2 Aufgeschobene Punkte

- **Variante A (Fragment-Migration):** bewusst zurückgestellt. Wenn nicht innerhalb der nächsten Monate ein Produkttreiber entsteht, sollte die Template-Infrastruktur (`templates/fragments/`, `{{include: …}}`-Resolver) aus dem Repo entfernt werden, statt halbfertig zu bleiben.
- **Variante C (strukturierte Daten als Ground Truth):** aufgeschoben bis konkreter Produkttreiber (PDF, MCP, Infografik). Die Schema-Arbeit dieser Entscheidung ist die Vorarbeit für Variante C, falls sie später doch gewählt wird.
- **Schema-Nutzung in Agent-Prompts:** Produzierende Agents (dep-scanner, stride-analyzer, orchestrator) duplizieren die Feldlisten der Artefakte heute im Prompt. Folgearbeit: Prompts auf Schema-Referenz umstellen.
- **CI-Durchsetzung:** `run-headless.sh` sollte `threat-model.yaml` nach Phase 11 gegen das neue Schema validieren. Blockiert Runs mit invalidem Output.

### 7.3 Wann diese Entscheidung neu bewertet werden muss

- Sobald ein Produkttreiber für PDF, MCP oder Infografik auftritt → Variante C neu bewerten.
- Sobald ein Dev-Team `install.sh`-Adoption explizit wünscht → Hybrid-Distribution neu bewerten.
- Sobald Schema-Änderungen häufig werden (>1× pro Quartal) → Versionierungsstrategie (`$id`-Pfad mit `/v2/`) anwenden statt Schema in-place zu ändern.

---

## 8. Kurzfassung für spätere Leser

- `schemas/` umgesetzt; vier YAML-Contracts inkl. neuem `threat-model.output.schema.yaml`.
- `templates/`-Fragment-Migration (Variante A) bewusst zurückgestellt — geringer Grenznutzen, hoher Prompt-Umbau.
- Variante B (Hybrid mit LLM-Platzhaltern) ausgeschlossen — Sackgasse.
- Variante C (strukturierte Daten als Ground Truth) aufgeschoben bis Produkttreiber vorliegt. Geschätzte Auswirkung dann: –25 bis –35 % Token-Kosten, –10 bis –15 % Laufzeit, deutlich bessere Layout-Konsistenz, leicht riskantere Narrative-Qualität, 3–6 Wochen Umbauaufwand.
- Distributionsmodell (Plugin vs. install.sh) bleibt Plugin — überlegen für zentrales AppSec-Team-Tooling. Hybrid-install.sh bleibt als optionaler Kanal offen.
