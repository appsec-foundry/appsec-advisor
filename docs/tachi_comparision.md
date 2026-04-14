# Vergleich: `appsec-plugin` vs. [tachi](https://github.com/davidmatousek/tachi)

Stand: 2026-04-14. Quellen: eigenes Repo (`plugin/CLAUDE.md`, Agent-Definitionen) und tachi README via WebFetch.

## TL;DR

Beide sind Claude-Code-Plugins für Threat Modeling, unterscheiden sich aber fundamental in der **Eingabe** und damit im Einsatzprofil:

| | **appsec-plugin** | **tachi** |
|---|---|---|
| **Eingabe** | Quellcode-Repo | Architektur-Diagramm (Mermaid, C4, PlantUML, ASCII, Freitext) |
| **Kernversprechen** | Evidenz-basiertes Threat Model mit file:line-Referenzen | Architektur-agnostisches Threat Model ohne Codezugriff |
| **Zielnutzer** | AppSec-Team + Dev-Team mit Repo-Zugriff | Security-Architekt, frühe Design-Phase, Multi-Stack-Reviews |
| **Invocation** | `/appsec-plugin:create-threat-model` (+ `check-appsec-requirements`) | 6 Commands: `/tachi.threat-model`, `/tachi.risk-score`, `/tachi.compensating-controls`, `/tachi.infographic`, `/tachi.security-report`, `/tachi.architecture` |

Sie sind **komplementär, nicht konkurrierend**. Tachi ist stärker im „Shift-Left vor dem ersten Commit", `appsec-plugin` ist stärker im „was ist im bestehenden Code wirklich drin".

---

## 1. Methodik

| Aspekt | appsec-plugin | tachi |
|---|---|---|
| Basis-Framework | STRIDE (6 Kategorien) | STRIDE (6) + LLM-spezifisch (Prompt Injection, Data Poisoning, Model Theft) + Agentic (Agent Autonomy, Tool Abuse) = **11 Kategorien** |
| AI/LLM-Abdeckung | OWASP LLM Top 10 (als Zusatzlinse pro Komponente, wenn `KNOWN_LLM_PATTERNS` erkannt) | Eigene dedizierte Agenten + **MAESTRO 7-Layer Mapping** (CSA) — L1 Foundation Model, L2 Data Ops, L3 Agent Framework, L4 Deployment Infra, L5 Eval & Observability, L6 Security & Compliance, L7 Agent Ecosystem |
| Supply-Chain | 5 Recon-Kategorien (unpinned Actions, Base-Images, Dep-Confusion, Postinstall, CI-Install-Integrität über 13 Ökosysteme) + dedizierte STRIDE-Muster | Nicht prominent dokumentiert |
| Requirements-Compliance | Phase 8b: YAML-basierte Requirements → verlinkt in Threats und Mitigations | Nicht vorhanden |
| Risk-Rating | Likelihood × Impact Matrix → Critical/High/Medium/Low | 4-dimensional: CVSS 3.1 + Exploitability + Scalability + Reachability + Governance-Felder (Owner, SLA, Disposition, Review Date) |
| Governance | Keine formale SDLC-Triad-Governance | **AOD Kit** (Agentic Oriented Development Kit): PM + Architect + Team Lead Sign-offs, Quality Gates, conventional commits + release-please |

**Fazit:** tachi hat die **formalere AI-Threat-Taxonomie** (MAESTRO), das **quantitativere Risk-Scoring** und **explizite Governance-Prozesse**. `appsec-plugin` hat die **engere Verzahnung mit Compliance-Requirements** und evidence-gebundene Findings.

---

## 2. Architektur / Agenten

| | appsec-plugin | tachi |
|---|---|---|
| Gesamt-Agenten | 7 (context-resolver, recon-scanner, dep-scanner, stride-analyzer, triage-validator, qa-reviewer + orchestrator) | 12 Threat-Agenten: 7 STRIDE-Agenten (inkl. 2 EoP-Instanzen), 3 LLM, 2 Agentic |
| STRIDE-Topologie | **1 Agent pro Komponente** (analysiert alle 6 Kategorien) | **1 Agent pro Kategorie** (+ LLM/Agentic-Trigger über Keywords wie "LLM", "agent", "orchestrator", "MCP") |
| Orchestrierungs-Tiefe | 11 Phasen + 3 Depth-Tiers (`quick`/`standard`/`thorough`) | 5 Phasen (Scope → Threats → Countermeasures → Assess → Report) + Phase 3.5 Cross-Layer Correlation |
| Besonderheit | Phase 10b Triage-Validator (Rating-Konsistenz), Phase 11 QA-Reviewer (als Stage-2 im Skill mit eigenem Turn-Budget) | Phase 3.5 Attack-Chain-Detection quer über MAESTRO-Layer L1–L7 |
| Retry/Lock | Sub-agent-Retry bei Fehlern, Lock-File für konkurrente Runs, Resume-from-Checkpoint | Nicht dokumentiert |

**Unterschiedliche Philosophien:** `appsec-plugin` parallelisiert **pro Komponente** und lässt einen Agenten alle STRIDE-Letter machen (spart Evidenz-Re-Reads). tachi parallelisiert **pro Kategorie** — das ist billig, weil tachi keinen Code liest.

---

## 3. Input

| | appsec-plugin | tachi |
|---|---|---|
| Quelle | Git-Repo (`--repo <path>`) | Architektur-Dokument (`docs/security/architecture.md`) |
| Code-Reads | Ja, mit Grep/Read, Evidenz als file:line | Nein — explizit „analyzes architecture, not code" |
| Kontext-Quellen | REST-Endpoint (optional), `docs/business-context.md`, `docs/known-threats.yaml`, Recon-Scan (26 Kategorien) | Architektur-Input in 5 Formaten: Mermaid, C4, PlantUML, ASCII, Freitext |
| Cross-Repo | Auto-Discovery von SCM-Siblings + SaaS-Integrationen (Category 7.25), probt Sibling-Threat-Models | Nicht dokumentiert |
| Incremental | Auto-Detect wenn `threat-model.md` existiert, nur geänderte Komponenten, Resume-from-Checkpoint | Baseline-Delta: new/resolved/unchanged/updated Findings über Läufe |
| Architektur-Autogenerierung | Nein (C4-Diagramme werden direkt generiert, aber ohne separate Architekturbeschreibung) | `/tachi.architecture` Command: leitet Architektur-Beschreibung aus Repo ab |

**Konsequenz:** `appsec-plugin` produziert **verifizierbare** Threats (jedes Finding verweist auf konkreten Code); tachi produziert **breitere** Threats auf Konzept-Ebene, ohne dass man prüfen kann, ob das Control im Code existiert.

---

## 4. Output

| | appsec-plugin | tachi |
|---|---|---|
| Kern-Reports | `threat-model.md` (mit VS-Code-Deep-Links), `threat-model.yaml`, `threat-model.sarif.json` | ~20 Artefakte über mehrere Commands verteilt |
| STRIDE-Findings | Threat Register mit CWE-IDs, Mitigation Register, Critical Findings, Management Summary | `threats.md`, `threats.sarif`, `threat-report.md` (Narrative) |
| Attack-Trees | Nein | `attack-trees/` Verzeichnis, Mermaid pro Critical/High Finding + `attack-chains.md` |
| Risk-Scoring | Qualitativ (Likelihood × Impact) integriert | Separater Command `/tachi.risk-score` → `risk-scores.md`, `risk-scores.sarif` |
| Compensating Controls | Section 7 (Security Controls Catalog mit ✅/⚠️/🔶/❌-Badges) | Separater Command `/tachi.compensating-controls` → `compensating-controls.md`, `.sarif`, residual-risk-Berechnung |
| Diagramme | C4 (Context/Container/Component) + Tech-Stack, automatisch aus Code; Nodes mit Medium+-Threats werden pink | Parsed Input-Diagramm, generiert Attack-Trees via mermaid-cli |
| PDF | Nein | **Ja** (Typst) — `security-report.pdf`, multi-page Booklet |
| Infographics | Nein | **Ja** — 5 Templates: `baseball-card`, `system-architecture`, `risk-funnel`, `maestro-stack`, `maestro-heatmap` (JPEG via Gemini API) |
| Executive-Summary | Management Summary als Section 0 (Risk Distribution, Top Findings, Priority Actions, Overall Rating, Requirements-Compliance-Subsection) | `/tachi.security-report` als PDF-Booklet |
| CI/CD | SARIF v2.1.0 (validated against schema), Headless-Runner, Lock-File | SARIF 2.1.0 (multiple Streams: threats, risk-scores, compensating-controls) |
| Stats/Metadaten | `run_statistics` Appendix mit Per-Phase-Duration, Token-Breakdown, Cost-Estimation | Non-Determinismus dokumentiert (+/- 10 % Finding-Varianz zwischen Läufen) |

**Unterschied:** tachi ist **präsentations-stärker** (PDF, Infographics, Attack-Trees) und strukturell **breiter gefächert** über mehrere Commands. `appsec-plugin` ist **developer-workflow-stärker** (klickbare file:line-Links, YAML für Pipelines, Requirements-Verlinkung, Single-Command für alles).

---

## 5. Ökosystem / Abhängigkeiten

| | appsec-plugin | tachi |
|---|---|---|
| Sprachen | Python (Hook-Scripts, Tests), ansonsten Markdown | Python 46 % / Shell 31 % / Typst 20 % / TypeScript 2 % |
| Externe Tools | **Keine** Pflicht-Tools; Dep-Scanner nutzt native (`npm audit`, `pip-audit`, `govulncheck`) wenn vorhanden | **Harte Requirements**: `typst` CLI + `@mermaid-js/mermaid-cli` (`mmdc`). Optional: `GEMINI_API_KEY` für Infographics |
| Installation | `claude --plugin-dir /path/to/appsec-plugin/plugin` — kein Restart nötig | `install.sh` kopiert in `.claude/` + **Claude-Code-Restart** erforderlich |
| Plattform | Linux/macOS/Windows (WSL), plattform-agnostisch | macOS/Linux via `brew`/`apt` |
| Tests | pytest-Suite (~440 Tests: agent-frontmatter, steering, SARIF-Schema, config-schema) | pytest, ≥80 % Coverage-Requirement via `make test` |
| Hooks | `UserPromptSubmit`-Steering-Hook mit tiered keyword matching (strong / code / action) | Nicht dokumentiert |
| Logging | Automatische Hook-Event-Logs, ASSESSMENT_SUMMARY, Log-Rotation bei 5 MB | Nicht dokumentiert |

---

## 6. Konfiguration & Erweiterbarkeit

| | appsec-plugin | tachi |
|---|---|---|
| Konfigurationsdateien | `plugin/config.json` (external context, pricing, logging), `skills/check-appsec-requirements/config.json` | Implizit via Architektur-Input und Flags |
| External Context | POST `rest_url` mit `{repo_url}` → Kontext-Injection in Phase 1 | Nicht vorhanden |
| Known Threats Input | `docs/known-threats.yaml` mit Statuses (`open`/`mitigated`/`accepted`/`false-positive`) → verbindliche Verifikation | Nicht vorhanden |
| Model-Override | `--stride-model opus` (~5× Kosten) per Agent-Tool-Override | Nicht dokumentiert |
| Depth-Control | `--assessment-depth quick/standard/thorough` steuert 7 interne Variablen | `--output-dir`, `--baseline`, `--version` Flags |
| Steering-Keywords | `hooks/steering_keywords.json` extern konfigurierbar | Nicht vorhanden |
| Pricing | Konfigurierbar pro Modell in `config.json` | Nicht vorhanden |

---

## 7. Stärken / Schwächen

### appsec-plugin — Stärken
- **Evidenz-gebunden**: jeder Threat hat file:line + Codesnippet, direkt überprüfbar
- **Requirements-Integration**: SEC-*-IDs fließen in Threats und Mitigations, Phase 8b-Compliance-Check
- **Recon-Breite**: 26 Security-Kategorien, Supply-Chain inkl. CI-Install-Integrität über 13 Ökosysteme
- **Cross-Repo-Awareness**: erkennt Siblings, SaaS, prüft deren Threat-Models
- **Auto-Incremental**: zweite und spätere Läufe teilen sich Ergebnisse wiederverwertbar
- **Depth-Tiers** mit harten Turn-Budgets → deterministische Kosten
- **Keine externen Binary-Abhängigkeiten** (rein Claude-Code + optional Python)
- **Resume-from-Checkpoint** nach fehlgeschlagenen Runs

### appsec-plugin — Schwächen
- Braucht Code-Zugriff → nicht brauchbar in Design-Phase vor Commit
- Keine dedizierten LLM/Agentic-Agenten (nur Zusatzlinse)
- Kein PDF/Infographic-Output
- Risk-Rating nur qualitativ (Matrix), kein CVSS-Vektor, keine Governance-Felder (SLA, Owner, Disposition)
- Kein MAESTRO-Layer-Mapping
- Kein separater Compensating-Controls-Command mit Residual-Risk-Berechnung

### tachi — Stärken
- **Multi-Stack**: funktioniert für jede Architektur, kein Sprach-Lock-In
- **Design-Phase-fit**: brauchbar, bevor Code existiert
- **Erste-Klasse AI-Threats**: MAESTRO-Layer, dedizierte Agenten, Attack-Chain-Detection quer über L1–L7
- **Präsentations-Output**: PDF (Typst), Infographics (5 Templates), Attack-Trees
- **Quantitatives Risk-Scoring**: CVSS + Exploitability + Scalability + Reachability + Governance
- **Baseline-Tracking**: new/resolved/unchanged/updated über Läufe sichtbar
- **Modularer Command-Split**: Risk-Scoring und Compensating-Controls als eigene, wiederholt aufrufbare Phasen
- **AOD-Kit-Governance**: explizite SDLC-Triad, Quality Gates, semantic releases

### tachi — Schwächen
- **Keine Code-Evidenz**: Findings bleiben konzeptionell, nicht verifizierbar gegen echten Code
- **Harte Tool-Abhängigkeiten**: `typst`, `mermaid-cli` (und für volle Features `GEMINI_API_KEY`)
- **~10 % Finding-Varianz zwischen Läufen** (laut eigenem README) — erschwert Regressions-Gating
- **Kein Requirements-Framework-Integration** dokumentiert
- **Keine Recon-Phase**: Qualität steht und fällt mit dem Input-Diagramm
- **Mehrere Commands notwendig** für vollständiges Artefakt-Set — höhere Orchestrierungs-Komplexität beim Nutzer
- **Claude-Code-Restart** nach Installation erforderlich

---

## 8. Einsatzszenarien — welches Tool wann?

| Szenario | Empfehlung |
|---|---|
| Bestehendes Repo, AppSec-Review mit konkreten Fix-Issues | **appsec-plugin** |
| Neue Architektur vor dem ersten Commit, RFC-Review | **tachi** |
| Compliance-Audit (PCI/SOC2 mit Requirements-Mapping) | **appsec-plugin** |
| LLM-Agent-System mit mehrschichtigen AI-Komponenten | **tachi** (MAESTRO + Attack-Chain) oder **appsec-plugin** mit LLM-Patterns — tachi tiefer bei Layering, appsec-plugin tiefer bei Code-Integration |
| Board-Report / Management-Präsentation | **tachi** (PDF + Infographics) |
| CI/CD-Gate mit Delta-Awareness | **appsec-plugin** (`--sarif`, harte Budgets, Lock-File) oder **tachi** (Baseline-Delta, mehrfache SARIF-Streams) — beide SARIF-fähig |
| Polyglot-Microservices ohne einheitlichen Repo-Zugriff | **tachi** |
| Supply-Chain-Risiko-Review (CI/CD, Dep-Confusion, Postinstall) | **appsec-plugin** |
| Residual-Risk-Berechnung mit Control-Audit | **tachi** (`/tachi.compensating-controls`) |
| Headless-CI-Run ohne externe Binaries | **appsec-plugin** |
| Quantitatives CVSS-basiertes Risikoregister | **tachi** (`/tachi.risk-score`) |

---

## 9. Mögliche Inspiration für `appsec-plugin`

Dinge aus tachi, die sich lohnen zu evaluieren:

1. **MAESTRO-Layer-Mapping** für Komponenten mit LLM-Patterns — zusätzliches Tag neben STRIDE in YAML/SARIF. Billig, falls nur als Label.
2. **CVSS-Vektor-Feld** im Threat-Schema als optionale Ergänzung zur Likelihood/Impact-Matrix — ermöglicht quantitative Regressions-Dashboards.
3. **Governance-Felder** im YAML-Schema: `owner`, `sla`, `disposition`, `review_date` pro Threat — erleichtert Ticket-System-Integration.
4. **Attack-Chain-Detection**: explizite Phase nach STRIDE-Merge, die Pfade über Threats/Komponenten hinweg identifiziert (heute implizit im Management-Summary).
5. **Dedizierte Agentic-Agenten** (Agent Autonomy, Tool Abuse) als eigene Threat-Lens zusätzlich zum OWASP-LLM-Block.
6. **Attack-Trees pro Critical/High Finding** als Mermaid-Dateien neben dem Haupt-Report.
7. **Delta-Output**: „neue / aufgelöste / unveränderte Threats seit letztem Lauf" als eigener Report (heute implizit im Incremental-Modus, nicht als Changelog ausgewiesen).
8. **PDF-Export via Typst** als optionales `--pdf` Flag — zielgruppenfreundlicher für Management-Reviews.
9. **Modularer Command-Split**: getrennter Risk-Scoring-Command, der ein bestehendes Threat-Model nachträglich quantifizieren kann.
10. **Infographic-Templates** (baseball-card, risk-funnel) für Awareness-Kampagnen und Stakeholder-Decks.

Nichts davon erfordert eine Architektur-Umstellung; alle Punkte sind additiv und könnten selektiv eingebaut werden.

---

## 10. Mögliche Inspiration für tachi (umgekehrt)

- Recon-Phase, die aus einem Repo automatisch eine Architektur-Beschreibung ableitet (`/tachi.architecture` geht in diese Richtung, aber ohne Security-Recon-Breite der 26 Kategorien).
- Requirements-Compliance-Linse (SEC-*-IDs in Findings, YAML-basierter Baseline-Check).
- Evidenz-Felder (file:line) wo Code-Zugriff verfügbar ist, um die 10 %-Varianz bei High-Severity-Findings zu senken.
- `--dry-run`-Modus mit Temp-Directory-Output für Preview ohne Repo-Mutation.
- Cross-Repo-Dependency-Discovery über SCM-Siblings und SaaS-SDK-Imports.
- Configurable External-Context-Endpoint für Team-Ownership, Compliance-Scope und prior findings.
