# Refactoring-Plan: Wartbarkeit, Qualität, Performance

**Status:** Vorschlag, nicht umgesetzt
**Erstellt:** 2026-05-12
**Ziele:** Wartbarkeit ↑, Qualität ↑, Performance messbar halten, Risiko niedrig
**Leitprinzip:** Das Plugin soll von Menschen verbessert werden können — strukturiert, nicht vibe-coded.

---

## Ausgangslage (verifiziert)

### Was gut ist

- **Deterministische Render-Pipeline:** LLM schreibt nur Fragmente, finale `threat-model.md` wird aus `sections-contract.yaml` + `compose_threat_model.py` gerendert. Hard Gate (`check_inline_shortcut.py`) erzwingt das.
- **Lazy-Load von Phase-Groups:** Der Orchestrator (`agents/appsec-threat-analyst.md:390, 412, 432`) lädt Phase-Group-Files erst zu Phasen-Grenzen, plus Fast-Path No-Op Exit für inkrementelle Runs.
- **Substring-basierte Drift-Guards:** `tests/test_dispatch_prompt_cache_order.py` und `test_agent_definitions.py` (23 Tests) prüfen Frontmatter, Marker-Reihenfolge, Pflichtsections.
- **Test-Disziplin:** 92 Testfiles, 2682 Testfälle (`pytest --collect-only -q -p no:cacheprovider`), viele "Promise-Keeping"-Tests gegen Schemas und Agent-Verträge.
- **Strukturierte Phase-Group-Files:** `phase-group-finalization.md` hat 49 Subheadings auf 2009 Zeilen — nicht Vibe-Coding, sondern strukturierter langer Text.

### Was schmerzt

| Schmerzpunkt | Verifizierte Zahl |
|---|---|
| `compose_threat_model.py` | 6937 LOC, 40+ Funktionen, 7 Manifest-Reader |
| `qa_checks.py` | 4909 LOC, 6+ Check-Kategorien, geteilter Regex/Label-Index-State |
| `phase-group-finalization.md` | 2009 LOC ≈ 44k Tokens |
| `phase-group-architecture.md` | 1557 LOC ≈ 34k Tokens |
| `phase-group-threats.md` | 1569 LOC ≈ 32k Tokens |
| `appsec-qa-reviewer.md` | 1688 LOC ≈ 42k Tokens |
| `appsec-stride-analyzer.md` | 555 LOC ≈ 15k Tokens |
| Fragment ↔ Producer ↔ Schema | Implizite Relation in mehreren Registries (`compose_threat_model.py`, `validate_fragment.py`, `qa_checks.py`, `sections-contract.yaml`), kein eigener Drift-Test |
| Drift-Guards | Substring-basiert, fangen keine semantische Drift |
| STRIDE-Coverage | LLM-probabilistisch, keine deterministische Faktenbasis |
| `eval()` mit restricted builtins | 2× (`compose_threat_model.py:363`, `qa_checks.py:1113`) — sandbox-bypass-fähig, aber Input aus vertrauenswürdigem Repo-File |

---

## Empfohlene Sequenz

```
A0 (0.5–1d) → A1 (1–1.5d) → A2 (0.5–1d) → B1 Pilot (3–4d) → C1 (1d)
```

**Kernplan: 6–8 Tage**, verteilt auf 5–6 PRs.

**B1 vollständig** bleibt sinnvoll, aber erst nach dem Pilot und nach Messdaten aus A0. **C2 (Semgrep)** ist bewusst aus dem Kernplan herausgenommen und als separates Experiment beschrieben, weil es eine neue Scanner-Dependency und neue Betriebsrisiken einführt.

Jede Phase ist eigenständig wertvoll. Stop nach Phase A oder nach dem B1-Pilot ist möglich, ohne dass Vorarbeit verfällt.

---

## Phase A — Fundament + Baseline

### A0 — Mess-Baseline konsolidieren (vor allen Performance-Behauptungen)

**Aufwand:** 0,5–1 Tag
**Risiko:** niedrig

**Was:** Vorhandene Telemetrie in eine reproduzierbare Run-Messung zusammenführen. Das ist **kein Greenfield-Parser**: Das Repo hat bereits `scripts/record_stage_stats.py`, `scripts/verify_run_costs.py`, `scripts/cost_running_total.py`, `.stage-stats.jsonl`, `.hook-events.log`, `SESSION_STOP` und `ASSESSMENT_TOKENS`.

Die Baseline soll erfassen:
- Tokens pro Phase (Input/Output, mit Cache-Hit/Miss-Aufschlüsselung)
- Tokens/Kosten pro Stage und, soweit möglich, pro Agent
- Wall-Time pro Stage und Phase
- Stop-Gründe (`max_turns`, `unknown`, `end_turn`) und Retry/Repair-Hinweise
- Kontext-Fenster-Auslastung am Höhepunkt (z.B. Phase 11)

**Warum:** Ohne Baseline behaupten wir Effekte, die wir nicht beweisen können. Alle folgenden Performance-Aussagen brauchen Vorher-/Nachher-Zahlen. Besonders wichtig: `SESSION_STOP`-Zeilen sind kumulativ; naive Summierung liefert falsche Kosten. `verify_run_costs.py` kennt diese Fallstricke bereits.

**Deliverable:**
- `scripts/measure_run.py` oder Erweiterung eines bestehenden Helpers — liest `.stage-stats.jsonl`, `.hook-events.log`, `.agent-run.log` und `verify_run_costs.py --json`, schreibt `.run-metrics.json`
- `tests/test_measure_run.py` — Smoke-Test gegen ein eingefrorenes Log-Beispiel
- Eine **Baseline-Messung** auf 2 Repos (Juice Shop + ein interner Use-Case), eingecheckt unter `docs/baselines/`

**Erfolgskriterien:** Skript läuft, Output stabil reproduzierbar, keine naive Doppelzählung kumulativer `SESSION_STOP`-Zeilen, Baseline-Dokumentation existiert.

---

### A1 — Fragment-Registry-Linter

**Aufwand:** 1–1,5 Tage
**Risiko:** niedrig

**Was:** Neues Skript `scripts/check_fragment_registry.py` + CI-Integration.

**Vorgehen:**

1. Parser für `data/sections-contract.yaml`: extrahiert alle Sections mit `fragment_type ∈ {data, hybrid, markdown}` und deren `fragment:` / `schema:`-Pfad.
2. Cross-Check:
   - Für `data`/`hybrid`: Existiert `schemas/fragments/<id>.schema.json`?
   - Stimmen die hartkodierten Maps überein?
     - `compose_threat_model.py:_SECTION_FRAGMENT_MAP`
     - `compose_threat_model.py:_KNOWN_JSON_FRAGMENT_SCHEMAS`
     - `validate_fragment.py:FRAGMENT_SCHEMAS`
     - `validate_fragment.py:_FRAGMENT_FILENAMES`
     - `qa_checks.py:CONTRACT_SECTION_FRAGMENTS`
   - Existiert für jede JSON-Fragment-Datei eine Registry-Zuordnung?
   - Umgekehrt: Jedes Schema in `schemas/fragments/` ist registriert und entweder im Contract oder in einer optionalen JSON-Fragment-Map erklärbar.
3. Einen expliziten Drift-Test hinzufügen. Der Composer-Kommentar verweist auf `tests/test_qa_fragment_map.py`, aber diese Datei existiert aktuell nicht; entweder diesen Test anlegen oder den Kommentar korrigieren.
4. Erst danach optional Producer-Erkennung ergänzen. AST-Suche nach `Path(...) / "<literal>"`, `f".fragments/{...}.json"` usw. ist nützlich, aber anfälliger für False Positives als der Registry-Abgleich.
5. Exit-Code 1 bei Drift, klare Fehlermeldung mit Datei+Zeile.
6. Test in `tests/test_fragment_registry.py` oder `tests/test_qa_fragment_map.py`, der das Skript gegen den aktuellen Repo-State laufen lässt.
7. CI-Integration: Erst als **Warning** in `.github/workflows/`, nach 4 Wochen auf Fail eskalieren.

**Mehrwert:**
- **Wartbarkeit:** Dokumentiert die wichtigste implizite Relation im Plugin als ausführbaren Code.
- **Qualität:** Drift wird im PR gefangen, nicht zur Laufzeit beim Endkunden.
- **Performance:** Kein direkter Effekt.

**Risiken:**
- Producer-Detection via AST kann False Positives produzieren. → Allow-List-Mechanismus mit klarem Kommentar pro Eintrag.
- CI-Gate, der bei legitimen Patterns rotscheint, frustriert. → Warning-First-Strategie.

**Erfolgskriterien:** Linter läuft auf aktueller Codebase clean. Künstlich eingefügter Drift (Schema gelöscht, Fragment-Pfad falsch, Map-Eintrag nur in `compose_threat_model.py` geändert) wird erkannt.

---

### A2 — Manifest-Reader extrahieren

**Aufwand:** 0,5–1 Tag
**Risiko:** niedrig

**Was:** `scripts/compose_threat_model.py` Zeilen 1127–1648 (7 `_read_*`-Funktionen + Helpers) → neues Modul `scripts/_manifest_readers.py`.

**Betroffene Funktionen:**
- `_read_package_json` (npm)
- `_read_project_manifest` (Top-Level-Dispatch)
- `_read_pyproject_toml`
- `_read_cargo_toml`
- `_read_go_mod`
- `_read_pom_xml`
- `_read_gradle`
- `_read_readme_description`
- `_read_readme_tags`
- `_read_license_file`
- `_format_author`, `_derive_homepage`, `_derive_runtime`, `_extract_repo_url`

**Vorgehen:**

1. Vor Move: Grep nach `@lru_cache`, `_CACHE`, `_CONST` auf Modul-Ebene innerhalb der zu verschiebenden Funktionen. Falls vorhanden, gleichzeitig mit verschieben.
2. Funktionen ins neue Modul verschieben, `ctx: RenderContext`-Abhängigkeiten als reine Parameter durchreichen.
3. API realistisch schneiden:
   - `read_project_manifest(ctx) -> dict`
   - entweder zusätzliche Exports für `format_author`, `read_license_file`, `derive_homepage`, `derive_runtime`, `extract_repo_url`, `read_readme_tags`
   - oder eine höhere API `enrich_project_metadata(ctx, project, meta, remote_url) -> dict`, damit `_render_infobox()` keine privaten Helper weiter direkt braucht.
4. Bestehende Tests in `test_compose_threat_model.py` bleiben unverändert (testen via Public API). Optional: neue Unit-Tests pro Reader in `test_manifest_readers.py`.
5. **Disziplin:** Move-PR macht **nichts anderes** als verschieben — kein Refactor, kein Rename, kein Logic-Change. Sonst zerstört es `git blame`.

**Mehrwert:**
- **Wartbarkeit:** Blueprint für spätere Section-Renderer-Extraktion. `compose_threat_model.py` von 6937 → ~6300 LOC.
- **Qualität:** Test-Ergonomie verbessert (pure functions ohne `RenderContext`-Fixture-Mock).
- **Performance:** Kein direkter Effekt.

**Risiken:**
- `git blame`-Churn für 7 Funktionen. Mitigation: Move-only-PR, `git log --follow` bleibt funktional.
- Merge-Konflikte auf offenen Branches. Mitigation: Vor dem Merge offene Branches scannen, kurzfristig durchwinken.
- Versteckter Modul-State. Mitigation: Vor-Grep (siehe Schritt 1).
- Zu enger Public-API-Schnitt. `_render_infobox()` nutzt mehrere Helper direkt; `read_project_manifest(ctx)` allein reicht nicht ohne kleine Anpassung der API-Grenze.

**Erfolgskriterien:** `compose_threat_model.py` LOC sinkt um ≥500. Alle bestehenden Tests grün. Public API unverändert.

---

## Phase B — Prompts strukturieren

### B1 — Phase-Group-Prompts modularisieren

**Aufwand:** Pilot 3–4 Tage; vollständige Umsetzung 12–18 Tage gesamt, in 4 Sub-PRs.
**Risiko:** mittel — Prompt-Restrukturierung kann subtil das LLM-Verhalten ändern.

**Was:** Jede `agents/phases/phase-group-*.md` aufteilen in eine Verzeichnis-Struktur:

```
agents/phases/phase-group-finalization/
├── README.md           # Index: wann was lesen
├── instructions.md     # Prozedurale Schritte (klein, ~400 LOC)
├── contracts.md        # Output-Schemas, Invarianten, Validierungs-Regeln
├── examples.md         # Konkrete Walkthrough-Beispiele (lazy-load on demand)
└── edge-cases.md       # Fallunterscheidungen, "was tun wenn X" (lazy-load on demand)
```

Backwards-Kompatibilität: `agents/phases/phase-group-finalization.md` bleibt als Shim, der auf das Verzeichnis verweist (oder die wichtigsten Files inline einbettet).

**Reihenfolge der Sub-PRs:**

1. **B1.1 — Pilot: `phase-group-architecture`** (3–4 Tage). Mittelgroße Phase-Group, kein Critical Path. Bewährt das Pattern. Nach diesem PR Stopp/Pivot erlauben.
2. **B1.2 — `phase-group-threats`** (3–4 Tage). Berührt STRIDE-Dispatch, wichtigste Phase.
3. **B1.3 — `phase-group-finalization`** (4–6 Tage). Größte Phase-Group, kritischster Output (Fragment-Authoring, Changelog, SARIF).
4. **B1.4 — `phase-group-recon`** (1–2 Tage). Kleinste, am wenigsten Aufwand. Optional, weil ohnehin nur 4k Tokens.

**Vorgehen pro Sub-PR:**

1. **Vor Restrukturierung:** Golden-Output auf 2 Repos einfrieren (Juice Shop, interner Use-Case). Einchecken unter `tests/golden/<phase-group>/`.
2. **Aufteilung:** Subheadings als natürliche Schnittlinien nutzen (49 in finalization!). Inhaltliche Zuordnung:
   - **instructions.md** — alles unter `### Phase X.Y` mit prozeduralen Verben
   - **contracts.md** — alle `Schema:`, `Fragment must encode:`, `Output format:` Blöcke
   - **examples.md** — alle `#### <konkretes-Beispiel>` Sub-Subheadings (z.B. `7.3.1 Password Login Flow`)
   - **edge-cases.md** — alle `**When X**`, `**If Y**`, `Fallback:` Sections
3. **Orchestrator-Anpassung:** `appsec-threat-analyst.md` Phase-Group-Read-Aufrufe verlängern um optionale Sub-File-Reads. Für den Pilot zuerst konservativ: Shim liest dieselben Inhalte wie vorher, aber aus mehreren Dateien. Erst nach Golden-Diff und A0-Messung selektiv auf `instructions.md` + `contracts.md` reduzieren. `examples.md` / `edge-cases.md` per Bedingung oder Just-in-Time bei Unklarheit.
4. **Drift-Guards anpassen:** `test_dispatch_prompt_cache_order.py` und `test_agent_definitions.py` Pfade aktualisieren.
5. **Nach Restrukturierung:** Re-Run auf den 2 Repos. Diff gegen Golden Output. **Akzeptanzkriterium:** Diff nur kosmetisch (Whitespace, Section-IDs falls neu, Zeilennummern). Inhaltliche Diffs in Threats, Findings, Mitigations sind **Blocker**.

**Mehrwert:**
- **Wartbarkeit (Hauptgewinn):** Eine Person, die Phase 11 modifizieren will, liest 400 LOC Instructions statt 2009 LOC Mixed-Content. Beispiele und Edge-Cases sind separat einsehbar.
- **Qualität:** Edge-Cases werden sichtbar statt in Prosa-Absätzen versteckt. Audit-Trail klarer.
- **Performance (sekundär, nicht garantiert):** Möglicher Kontext-Fenster-Headroom, wenn Subfiles wirklich selektiv geladen werden. Der Gewinn ist wahrscheinlich kleiner als eine reine Dateigrößenrechnung suggeriert, weil Stage 2 inzwischen vom schlanken `agents/appsec-threat-renderer.md` übernommen wird und nicht mehr blind den ganzen Finalization-Prompt braucht. Token-Einsparung nur nach A0-Messung behaupten.

**Risiken:**
- **LLM-Verhaltens-Drift:** Mitigation durch Golden-Output-Diffing (siehe oben). Bei Diff: Revert, andere Aufteilung versuchen.
- **Loader-Komplexität im Orchestrator:** Mitigation durch konservativen Default (alle Sub-Files lesen außer `examples.md`/`edge-cases.md`).
- **Lange Restrukturierungs-Phase:** 4 Sub-PRs über mehrere Wochen. Mitigation durch klare Ziel-Architektur in einer Issue-Beschreibung, auf die alle Sub-PRs referenzieren.
- **Überschätzter Performance-ROI:** Mitigation durch Pilot + A0-Messung. Wenn der aktive Stage-2-Kontext kaum sinkt, B1 als reine Wartbarkeitsarbeit bewerten und nicht als Kostenhebel verkaufen.

**Erfolgskriterien:**
- Pro Phase-Group: Golden-Output bleibt inhaltlich identisch.
- LOC-Volumen pro File ≤ 800 nach Aufteilung.
- Kontext-Fenster-Auslastung in Phase 11 sinkt messbar (siehe A0-Baseline).

---

### B2 — `appsec-qa-reviewer.md` strukturieren (verschoben)

**Aufwand:** 2 Tage
**Risiko:** mittel

**Status:** Aus aktueller Sequenz **herausgenommen**. Begründung:
- QA-Reviewer läuft nur 1–2× pro Run (statt 30+ Turns wie Orchestrator in Phase 11)
- Kontext-Fenster-Druck deutlich geringer
- Wartbarkeits-Gewinn vorhanden, aber niedriger ROI als Phase-Group-Restrukturierung

**Wieder aufgreifen wenn:**
- B1 erfolgreich abgeschlossen und das Pattern bewährt
- QA-Reviewer-Repair-Loops häufiger Budget exhausten (per A0-Metriken überwachbar)

---

## Phase C — Qualitäts- und Performance-Layer

### C1 — Strukturelle Drift-Guards

**Aufwand:** 1 Tag
**Risiko:** niedrig

**Was:** Bestehende Substring-Asserts erweitern um:

1. **Token-Count-Bounds pro Prompt-File.** Per AST oder Heuristik (chars/4). Failure: "Prompt X grew from N to M tokens (>15% increase) — review intended?"
2. **Required-Section-Presence statt nur Required-Strings.** Beispiel: `instructions.md` MUSS einen `## Phase N` Heading haben für jeden in `sections-contract.yaml` deklarierten Phase-Step.
3. **Optional (deferred):** LLM-as-Judge-Test (Sonnet liest Prompt + 5 strukturelle Fragen). Gated, läuft nur im Nightly-CI. Erst sinnvoll nach B1.

**Mehrwert:**
- **Wartbarkeit:** Regressions-Schutz für die Investition aus B1.
- **Qualität:** Fängt subtile Prompt-Verschlechterungen (Token-Bloat, gelöschte Sections).
- **Performance:** Token-Bounds verhindern stille Bloat-Regressionen.

**Risiken:**
- Token-Count-Bounds zu eng → False Positives bei legitimen Erweiterungen. Mitigation: 20% Toleranz pro File, override per Kommentar im Test möglich.

**Erfolgskriterien:** Künstlich eingefügter Bloat (+30% Tokens) oder gelöschte Phase-Sections triggern Test-Failure.

---

### C2 — Semgrep als Triage-Cross-Check (separates Experiment, nicht Kernplan)

**Aufwand:** 3–5 Tage
**Risiko:** mittel (neue Scanner-Dependency, neue Runtime-Pfade, potenzielle Ergebnisdrift)

**Status:** Nicht Teil der empfohlenen Kernsequenz. Erst als opt-in Experiment starten, wenn A0/A1/A2 abgeschlossen sind und jemand Ownership für Ruleset und Betrieb übernimmt.

**Was:** Neue optionale Ergänzung: Semgrep-Run mit kuratiertem, lokal gepinntem Ruleset, Output als zusätzliches `.semgrep-cross-check.json`. Wird **nicht** dem STRIDE-Analyzer als Faktenbasis gefüttert und darf Ratings nicht automatisch erhöhen, sondern liefert nur Triage-Hinweise.

**Vorgehen:**

1. Optional hinter `--enable-semgrep`-Flag (default off). Kein versteckter Default-Run.
2. Nur lokaler/offline Lauf. Keine Cloud-Uploads, keine Telemetrie, kein Runtime-Download von Rules.
3. Ruleset pinnen. `p/owasp-top-ten` nur als Quelle für eine vendored/pinned Baseline verwenden, nicht als live heruntergeladene Referenz.
4. Output-Schema: `.semgrep-cross-check.json` mit Rule-ID, Pfad, Zeile, Severity, CWE/OWASP-Mapping, Fingerprint, Mapping zu existierenden LLM-Findings.
5. Phase 10b-Triage-Validator-Anpassung:
   - Semgrep-Fund deckt sich mit LLM-Finding → Flag `semgrep_corroborated`.
   - Semgrep High/ERROR ohne passende LLM-Finding → Flag `coverage_gap_suspect`.
   - Kein Semgrep-Fund → keine Abwertung, kein "clean" Signal.
6. Timeout und graceful fallback. Semgrep-Crash oder fehlende Binary darf den Pflichtpfad nicht brechen.
7. Auditierbarkeit: Optionaler "Cross-Check Summary" im Run-Statistics-Appendix oder Completion Summary, aber nicht als neue Finding-Quelle im Hauptreport.

**Mehrwert:**
- **Qualität (Hauptgewinn):** Auditierbarkeit. Findings mit Semgrep-Rule-IDs sind nachvollziehbar. Reduziert "LLM hat es so eingeschätzt"-Beanstandungen.
- **Performance:** In der advisory-only Variante marginal bis null. Token-Ersparnis erst dann realistisch, wenn Semgrep-Funde in STRIDE-Evidence einfließen dürfen — das ist bewusst nicht Teil dieses Experiments.
- **Wartbarkeit:** Leicht negativ (mehr Code, neue Dependency). Mitigation: Optional, kein Eingriff in Pflicht-Pfad.

**Risiken:**
- **Ruleset-Pflege als Dauerverpflichtung.** Mitigation: Erstmal nur eine lokal gepinnte Baseline aus bekannten Semgrep-Regeln, keine Live-Downloads und keine eigenen Rules ohne klaren Owner.
- **False-Positive-Amplifikation.** Semgrep-Severity darf keine automatische `Critical`/`High`-Eskalation, CVSS-Vergabe oder P1/P2-Priorisierung auslösen.
- **False Confidence.** Ein leerer Semgrep-Run darf nie als "keine Schwachstellen" interpretiert werden.
- **Reproduzierbarkeit.** Live-Rulesets ändern sich. Ohne lokal gepinnte Regeln sind Reports schwer vergleichbar.
- **Datenschutz/Source Exposure.** Semgrep muss strikt lokal/offline laufen.
- **T-ID-Stabilität.** Wenn Semgrep-Funde später Findings erzeugen, kann ID-Churn entstehen. Im Experiment daher nur Flags, keine neuen `T-NNN`/`F-NNN`.
- **Operationelles Risiko (Semgrep-Crash, Timeout).** Mitigation: Optional + graceful fallback ohne Hard-Fail.

**Erfolgskriterien:**
- Auf einem Test-Repo: Semgrep findet ≥3 Findings, die mit LLM-Findings kreuzvalidiert werden können.
- Run mit `--enable-semgrep` ist nicht langsamer als +15% Wall-Time.
- Ein leerer oder fehlerhafter Semgrep-Lauf verändert keine Ratings, IDs oder Report-Struktur.

---

## Bewusst nicht im Plan

| Item | Begründung |
|---|---|
| `eval()` ersetzen | Reines Hygiene-Issue, kein direkter Beitrag zu Wartbarkeit/Qualität/Performance. Als 1-Stunden-Ausweich-PR irgendwann mitnehmen, nicht jetzt. |
| `qa_checks.py` splitten | Hohe Kopplung (geteilter Regex/Label-Index-State), hohes Refactoring-Risiko. Erst nach Phase B angehen, wenn man eingespielt ist. |
| Semgrep-Vollversion (als LLM-Faktenbasis) | Hohes Risiko: LLM-Vertrauen-Regression, False-Positive-Amplifikation, T-ID-Migration teuer. Passt nicht zu "niedriges Risiko". |
| Semgrep im Kernplan | Neue Dependency und Betriebspfad. Erst als opt-in Experiment nach A0/A1/A2 sinnvoll. |
| Prompts → YAML/Code | Radikal, ungetestet. Erst nach B1 mit Prototyp evaluieren. |
| Semantische LLM-as-Judge-Drift-Tests | Cost-intensiv. Erst nach B1 sinnvoll. |

---

## Erwartete Effekte

| Metrik | Baseline (A0 misst) | Nach Plan | Quelle des Gewinns |
|---|---|---|---|
| LOC im größten File | 6937 (`compose_threat_model.py`) | ~6300 | A2 |
| LOC im größten Prompt-File | 2009 (`phase-group-finalization.md`) | ≤800 pro Sub-File | B1 |
| Tokens in Phase 11 | ~44k | ~25–30k aktiver Kontext | B1 |
| Kontext-Fenster-Headroom | abnehmend | +30–40k Tokens | B1 |
| Token-Kosten pro Run | Baseline | **nicht vorab zusagen**; erwartbar eher einstellige % ohne weitere STRIDE-Änderungen | B1, falls selektives Laden tatsächlich greift |
| Wall-Time pro Run | Baseline | **nicht vorab zusagen**; nur messen | A0 + B1 |
| Audit-Trail-Qualität | Prosa-basiert | Optional mit Rule-IDs aus Semgrep | C2-Experiment |
| Drift-Detection im CI | Substring | Strukturell + Token-Bounds | C1 |

**Wichtig:** Performance-Effekte sind Hypothesen. A0 misst sie. Wenn Realität von Schätzung abweicht: dokumentieren und Plan anpassen, nicht ignorieren.

---

## Wartbarkeits-Skala (verifiziert)

| Stand | Skala 1–10 |
|---|---|
| Heute | ~5,5 |
| Nach Phase A (A0+A1+A2) | ~6 |
| Nach Phase B1 | ~7 |
| Nach Phase B1 + C1 | ~7–7,5 |

Delta: ~1,5–2 Punkte über den Kernplan. Der größte Sprung kommt durch B1, falls der Pilot zeigt, dass die Struktur ohne Verhaltensdrift funktioniert.

---

## Offene Fragen vor Start

1. **Wer pflegt das Semgrep-Ruleset langfristig?** Wenn niemand → C2 bleibt außerhalb des Kernplans.
2. **Sind Golden-Output-Tests politisch akzeptabel?** B1 hängt davon ab. Falls Test-Lauf-Kosten ein Problem sind, gibt es alternative Verifikationsstrategien (Diff auf Strukturebene statt Full-Output).
3. **Welche zwei Repos sind die "kanonischen" Test-Cases?** Juice Shop ist offensichtlich, das zweite muss gewählt werden — idealerweise ein Repo mit unterschiedlichem Profil (z.B. Python statt JS, Microservices statt Monolith).
4. **Soll B2 (QA-Reviewer) jemals nachgezogen werden?** Falls Repair-Loops in der Praxis Budget exhausten, ja. Sonst dauerhaft verschieben.

---

## Quellenangaben (verifiziert während Plan-Erstellung)

- Lazy-Load-Mechanismus: `agents/appsec-threat-analyst.md:202, 245, 388-432`
- Drift-Guard-Stil: `tests/test_dispatch_prompt_cache_order.py` (substring-asserts), `tests/test_agent_definitions.py` (Frontmatter-Validation, 23 Tests)
- Phase-Group-Struktur: `agents/phases/phase-group-finalization.md` (49 Subheadings, 98 Code-Fences, 2009 LOC)
- Budget-Exhaustion-Vorfall: `tests/test_agent_definitions.py:24-28` (Kommentar zur 75→120-Turn-Erhöhung)
- Fragment-Registry-Lücke: `data/sections-contract.yaml` (11 Fragmente deklariert) vs. `schemas/fragments/` (7 Schemas) — Unterschied legitim wegen `fragment_type: markdown`/`computed`, aber **kein** automatischer Cross-Check vorhanden.
- Fragment-Registry-Realität: `compose_threat_model.py`, `validate_fragment.py`, `qa_checks.py` und `sections-contract.yaml` enthalten mehrere überlappende Maps. `compose_threat_model.py` verweist auf `tests/test_qa_fragment_map.py`, die Datei existiert aktuell nicht.
- Stage-2-Renderer: `agents/appsec-threat-renderer.md` ist bereits schlank und lädt nicht den ganzen Finalization-Prompt; B1 ist daher primär Wartbarkeit, nicht garantiert Performance.
- Messpfade: `record_stage_stats.py`, `verify_run_costs.py`, `cost_running_total.py`, `.stage-stats.jsonl`, `.hook-events.log`, `SESSION_STOP`, `ASSESSMENT_TOKENS`.
- Semgrep: derzeit keine Integration im Repo; Treffer nur in diesem Plan.
- `eval()`-Stellen: `scripts/compose_threat_model.py:363`, `scripts/qa_checks.py:1113`
- Monolith-Größen: gemessen via `wc -l`
- Token-Schätzungen: bytes/4 als Approximation

---

**Dieser Plan ist ein Vorschlag. Vor Umsetzung: Diskussion + Priorisierung im Team. Insbesondere die Offenen Fragen 1–4 klären.**
