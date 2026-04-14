# Vergleich: `appsec-plugin` vs. [tachi](https://github.com/davidmatousek/tachi)

Stand: 2026-04-14. Quellen: eigenes Repo (`plugin/CLAUDE.md`, Agent-Definitionen) und tachi README via WebFetch.

## TL;DR

Beide sind Claude-Code-Plugins für Threat Modeling, unterscheiden sich aber fundamental in der **Eingabe** und damit im Einsatzprofil:

| | **appsec-plugin** | **tachi** |
|---|---|---|
| **Eingabe** | Quellcode-Repo | Architektur-Diagramm (Mermaid, C4, PlantUML, ASCII, Freitext) |
| **Kernversprechen** | Evidenz-basiertes Threat Model mit file:line-Referenzen | Architektur-agnostisches Threat Model ohne Codezugriff |
| **Zielnutzer** | AppSec-Team + Dev-Team mit Repo-Zugriff | Security-Architekt, frühe Design-Phase, Multi-Stack-Reviews |

Sie sind **komplementär, nicht konkurrierend**. Tachi ist stärker im „Shift-Left vor dem ersten Commit", `appsec-plugin` ist stärker im „was ist im bestehenden Code wirklich drin".

---

## 1. Methodik

| Aspekt | appsec-plugin | tachi |
|---|---|---|
| Basis-Framework | STRIDE (6 Kategorien) | STRIDE + LLM-Spezifisch (Prompt Injection, Data Poisoning, Model Theft) + Agentic (Agent Autonomy, Tool Abuse) = **11 Kategorien** |
| AI/LLM-Abdeckung | OWASP LLM Top 10 (als Zusatzlinse pro Komponente, wenn `KNOWN_LLM_PATTERNS` erkannt) | Eigene dedizierte Agenten + **MAESTRO 7-Layer Mapping** (CSA) |
| Supply-Chain | 5 Recon-Kategorien (unpinned Actions, Base-Images, Dep-Confusion, Postinstall, CI-Install-Integrität) + dedizierte STRIDE-Muster | Nicht prominent dokumentiert |
| Requirements-Compliance | Phase 8b: YAML-basierte Requirements → verlinkt in Threats und Mitigations | Nicht vorhanden |
| Risk-Rating | Likelihood × Impact Matrix → Critical/High/Medium/Low | 4-dimensional: CVSS 3.1 + Exploitability + Scalability + Reachability + Governance-Felder (Owner, SLA, Disposition) |

**Fazit:** tachi hat die **formalere AI-Threat-Taxonomie** (MAESTRO) und das **quantitativere Risk-Scoring**. `appsec-plugin` hat die **engere Verzahnung mit Compliance-Requirements** und evidence-gebundene Findings.

---

## 2. Architektur / Agenten

| | appsec-plugin | tachi |
|---|---|---|
| Gesamt-Agenten | 7 (context-resolver, recon-scanner, dep-scanner, stride-analyzer, triage-validator, qa-reviewer + orchestrator) | 12 Threat-Agenten + Orchestrator/Dedup/Correlation-Utilities |
| STRIDE-Topologie | **1 Agent pro Komponente** (analysiert alle 6 Kategorien) | **1 Agent pro Kategorie** (plus LLM/Agentic) |
| Orchestrierungs-Tiefe | 11 Phasen + 3 Depth-Tiers (`quick`/`standard`/`thorough`) | 5 Phasen (Scope → Threats → Countermeasures → Attack-Chain → Assess) |
| Besonderheit | Phase 10b Triage-Validator (Rating-Konsistenz), Phase 11 QA-Reviewer (als Stage-2 im Skill) | Phase 3.5 Attack-Chain-Detection quer über MAESTRO-Layer |

**Unterschiedliche Philosophien:** `appsec-plugin` parallelisiert **pro Komponente** und lässt einen Agent alle STRIDE-Letter machen (spart Evidenz-Re-Reads, siehe Analyse in vorherigem Turn). tachi parallelisiert **pro Kategorie** — das ist billig, weil tachi keinen Code liest.

---

## 3. Input

| | appsec-plugin | tachi |
|---|---|---|
| Quelle | Git-Repo (`--repo <path>`) | Architektur-Dokument |
| Code-Reads | Ja, mit Grep/Read, Evidenz als file:line | Nein — explizit „analyzes architecture, not code" |
| Kontext-Quellen | REST-Endpoint (optional), `docs/business-context.md`, `docs/known-threats.yaml`, Recon-Scan (26 Kategorien) | Architektur-Input in 5 Formaten: Mermaid, C4, PlantUML, ASCII, Freitext |
| Cross-Repo | Auto-Discovery von SCM-Siblings + SaaS-Integrationen (Category 7.25), probt Sibling-Threat-Models | Nicht dokumentiert |
| Incremental | Auto-Detect wenn `threat-model.md` existiert, nur geänderte Komponenten | Baseline-Delta: new/resolved/unchanged/updated Findings über Läufe |

**Konsequenz:** `appsec-plugin` produziert **verifizierbare** Threats (jedes Finding verweist auf konkreten Code); tachi produziert **breitere** Threats auf Konzept-Ebene, ohne dass man prüfen kann, ob das Control im Code existiert.

---

## 4. Output

| | appsec-plugin | tachi |
|---|---|---|
| Kern-Reports | `threat-model.md` (mit VS-Code-Deep-Links), `.yaml`, `.sarif.json` | ~20 Artefakte: Findings (MD), SARIF 2.1.0, Attack-Trees, Risk-Scores, Compensating-Controls, Infographics (JPEG via Gemini), PDF-Report (Typst) |
| Diagramme | C4 (Context/Container/Component) + Tech-Stack, automatisch aus Code | Parsed Input-Diagramm, generiert Attack-Tree via mermaid-cli |
| PDF | Nein | Ja (Typst) |
| Infographics | Nein | 5 Templates (baseball-card, risk-funnel, maestro-stack, …) via Gemini API |
| Executive-Summary | Management Summary als Section 0 (risk distribution, top findings, priority actions, overall rating) | „Professional PDF report generation" + „security-report" Command |
| CI/CD | SARIF v2.1.0 (validated against schema), Headless-Runner, Lock-File, GitHub Advanced Security kompatibel | SARIF 2.1.0 für GitHub Code Scanning |

**Unterschied:** tachi ist **präsentations-stärker** (PDF, Infographics, Attack-Trees); `appsec-plugin` ist **developer-workflow-stärker** (klickbare file:line-Links, YAML für Pipelines, Requirements-Verlinkung).

---

## 5. Ökosystem / Abhängigkeiten

| | appsec-plugin | tachi |
|---|---|---|
| Sprachen | Python (Hook-Scripts, Tests), ansonsten Markdown | Python 46% / Shell 31% / Typst 20% |
| Externe Tools | keine Pflicht-Tools; Dep-Scanner nutzt native (`npm audit`, `pip-audit`, `govulncheck`) wenn vorhanden | **Harte Requirements**: `typst`, `@mermaid-js/mermaid-cli`. Optional: `GEMINI_API_KEY` |
| Installation | `claude --plugin-dir /path/to/appsec-plugin/plugin` | `install.sh` kopiert in `.claude/` + Claude-Code-Restart |
| Tests | pytest-Suite (agent-frontmatter, steering, SARIF-Schema, config-schema) | pytest, ≥80% Coverage |

---

## 6. Stärken / Schwächen

### appsec-plugin — Stärken
- **Evidenz-gebunden**: jeder Threat hat file:line + Codesnippet, direkt überprüfbar
- **Requirements-Integration**: SEC-*-IDs fließen in Threats und Mitigations, Phase 8b-Compliance-Check
- **Recon-Breite**: 26 Security-Kategorien, Supply-Chain inkl. CI-Install-Integrität über 13 Ökosysteme
- **Cross-Repo-Awareness**: erkennt Siblings, SaaS, prüft deren Threat-Models
- **Auto-Incremental**: zweite und spätere Läufe teilen sich Ergebnisse wiederverwertbar
- **Depth-Tiers** mit harten Turn-Budgets → deterministische Kosten

### appsec-plugin — Schwächen
- Braucht Code-Zugriff → nicht brauchbar in Design-Phase vor Commit
- Keine dedizierten LLM/Agentic-Agenten (nur Zusatzlinse)
- Kein PDF/Infographic-Output
- Risk-Rating nur qualitativ (Matrix), kein CVSS-Vektor
- Kein MAESTRO-Layer-Mapping

### tachi — Stärken
- **Multi-Stack**: funktioniert für jede Architektur, kein Sprach-Lock-In
- **Design-Phase-fit**: brauchbar, bevor Code existiert
- **Erste-Klasse AI-Threats**: MAESTRO-Layer, Attack-Chain-Detection quer über L1–L7
- **Präsentations-Output**: PDF (Typst), Infographics (5 Templates), Attack-Trees
- **Quantitatives Risk-Scoring**: CVSS + Exploitability + Scalability + Reachability + Governance
- **Baseline-Tracking**: new/resolved/unchanged/updated über Läufe sichtbar

### tachi — Schwächen
- **Keine Code-Evidenz**: Findings bleiben konzeptionell, nicht verifizierbar gegen echten Code
- **Harte Tool-Abhängigkeiten**: `typst`, `mermaid-cli` (und für volle Features `GEMINI_API_KEY`)
- **~10 % Finding-Varianz zwischen Läufen** (laut eigenem README) — erschwert Regressions-Gating
- **Kein Requirements-Framework-Integration** dokumentiert
- **Keine Recon-Phase**: Qualität steht und fällt mit dem Input-Diagramm

---

## 7. Einsatzszenarien — welches Tool wann?

| Szenario | Empfehlung |
|---|---|
| Bestehendes Repo, AppSec-Review mit konkreten Fix-Issues | **appsec-plugin** |
| Neue Architektur vor dem ersten Commit, RFC-Review | **tachi** |
| Compliance-Audit (PCI/SOC2 mit Requirements-Mapping) | **appsec-plugin** |
| LLM-Agent-System mit mehrschichtigen AI-Komponenten | **tachi** (MAESTRO) oder **appsec-plugin** mit LLM-Patterns — tachi tiefer bei Layering, appsec-plugin tiefer bei Code-Integration |
| Board-Report / Management-Präsentation | **tachi** (PDF + Infographics) |
| CI/CD-Gate mit Delta-Awareness | **appsec-plugin** (`--sarif`, harte Budgets, Lock-File) oder **tachi** (Baseline-Delta) — beide SARIF-fähig |
| Polyglot-Microservices ohne einheitlichen Repo-Zugriff | **tachi** |
| Supply-Chain-Risiko-Review (CI/CD, Dep-Confusion) | **appsec-plugin** |

---

## 8. Mögliche Inspiration für `appsec-plugin`

Dinge aus tachi, die sich lohnen zu evaluieren:

1. **MAESTRO-Layer-Mapping** für Komponenten mit LLM-Patterns — zusätzliches Tag neben STRIDE in YAML/SARIF. Billig, falls nur als Label.
2. **CVSS-Vektor-Feld** im Threat-Schema als optionale Ergänzung zur Likelihood/Impact-Matrix — ermöglicht quantitative Regressions-Dashboards.
3. **Attack-Chain-Detection**: explizite Phase nach STRIDE-Merge, die Pfade über Threats/Komponenten hinweg identifiziert (heute implizit im Management-Summary).
4. **Dedizierte Agentic-Agenten** (Agent Autonomy, Tool Abuse) als eigene Threat-Lens zusätzlich zum OWASP-LLM-Block.
5. **Delta-Output**: „neue / aufgelöste / unveränderte Threats seit letztem Lauf" als eigener Report (heute ist das implizit im Incremental-Modus, aber nicht als Changelog ausgewiesen).
6. **PDF-Export via Typst** als optionales `--pdf` Flag — zielgruppenfreundlicher für Management-Reviews.

Nichts davon erfordert eine Architektur-Umstellung; alle Punkte sind additiv und könnten selektiv eingebaut werden.

---

## 9. Mögliche Inspiration für tachi (umgekehrt)

- Recon-Phase, die aus einem Repo automatisch eine Architektur-Beschreibung ableitet (tachis `/tachi.architecture` geht in diese Richtung, aber ohne Security-Recon-Breite).
- Requirements-Compliance-Linse (SEC-*-IDs in Findings).
- Evidenz-Felder (file:line) wo Code-Zugriff verfügbar ist, um die 10 %-Varianz bei High-Severity-Findings zu senken.
