# Refactoring-Plan: Wartbarkeit, Qualität, Performance

**Status:** Vorschlag, nicht umgesetzt
**Erstellt:** 2026-05-12
**Aktualisiert:** 2026-05-13 (Folge) — **Quick-Wins R2/R3/R6/R10 gemergt** (Hintergrund in `bugs.md` / Session-Audit, **nicht** Teil dieses Plans): `compose_threat_model.RenderContext._build_label_index` ersetzt drei Linear-Loops in `lookup_label` (compose +19 LOC), `_PrePass.contract` jetzt tatsächlich genutzt — 5 redundante Contract-Loader in `qa_checks` entfernt (qa_checks −14 LOC), `check_infobox_completeness` Required-Set an `sections-contract.yaml` angeglichen (`license` rein, `description` raus), `check_toc_closure` baut Lowercase-Anchor-Set einmal vorab. Strategie unverändert; reine Drift-Korrektur an Zeilennummern/LOC im Plan-Text (siehe Tabellen unten). 2026-05-13 — **M10 ergänzt** (`eval_condition` → deterministischer Pattern-Resolver) als Phase-D-Item nach Sicherheits-Review: Regex-Sandbox-Pattern ist heute nicht ausnutzbar, aber für ein AppSec-Plugin nicht "obviously correct" und kollidiert mit der in `SECURITY.md` neu dokumentierten Untrusted-Repo-Richtung. Trace über alle 5 Call-Sites ergab: nur bare-name Bool-Lookups erreichen heute `eval()` — 15-LOC Pattern-Resolver ersetzt `eval()` komplett, statt es nur per AST-Walker zu zähmen. Vier YAML-Felder, die wie Conditions aussehen aber von keinem Python-Code gelesen werden, als Folge-Cleanup-Empfehlung dokumentiert. `eval()`-Eintrag aus "Bewusst nicht im Plan" entfernt. 2026-05-12 — Semgrep-Track (C2) gestrichen, Phase D (Tooling/Doku/Konsolidierung) ergänzt nach Verifikations-Pass gegen aktuellen Repo-State. M5 (`from __future__ import annotations`) gestrichen — Plan attestierte sich selbst "semantisch leer", null verifizierbarer Nutzen. Verifikations-Refresh: Stale LOC-Zahlen auf HEAD aktualisiert, Subheading-Count auf `phase-group-finalization.md` korrigiert (49 → 51), Open Question 4 empirisch beantwortet (Phase-Prompts überwiegend mensch-editiert), M1↔A0-Sequenz als orthogonal geklärt mit Empfehlung "Pre- und Post-M1-Baseline".
**Ziele:** Wartbarkeit ↑, Qualität ↑, Performance messbar halten, Risiko niedrig
**Leitprinzip:** Das Plugin soll von Menschen verbessert werden können — strukturiert, nicht vibe-coded.

---

## Ausgangslage (verifiziert)

### Was gut ist

- **Deterministische Render-Pipeline:** LLM schreibt nur Fragmente, finale `threat-model.md` wird aus `sections-contract.yaml` + `compose_threat_model.py` gerendert. Hard Gate (`check_inline_shortcut.py`) erzwingt das.
- **Lazy-Load von Phase-Groups:** Der Orchestrator (`agents/appsec-threat-analyst.md:390, 412, 432`) lädt Phase-Group-Files erst zu Phasen-Grenzen, plus Fast-Path No-Op Exit für inkrementelle Runs.
- **Substring-basierte Drift-Guards:** `tests/test_dispatch_prompt_cache_order.py` und `test_agent_definitions.py` (23 Tests) prüfen Frontmatter, Marker-Reihenfolge, Pflichtsections.
- **Test-Disziplin:** 92 Testfiles, 2698 Testfälle (`pytest --collect-only -q -p no:cacheprovider`), viele "Promise-Keeping"-Tests gegen Schemas und Agent-Verträge.
- **Strukturierte Phase-Group-Files:** `phase-group-finalization.md` hat 51 Subheadings (46× `###` + 5× `####`) auf 2009 Zeilen — nicht Vibe-Coding, sondern strukturierter langer Text.

### Was schmerzt

| Schmerzpunkt | Verifizierte Zahl |
|---|---|
| `compose_threat_model.py` | 6989 LOC, 41+ Funktionen, 7 Manifest-Reader |
| `qa_checks.py` | 5212 LOC, 6+ Check-Kategorien, geteilter Regex/Label-Index-State |
| `phase-group-finalization.md` | 2009 LOC ≈ 44k Tokens |
| `phase-group-architecture.md` | 1557 LOC ≈ 34k Tokens |
| `phase-group-threats.md` | 1631 LOC ≈ 33k Tokens |
| `appsec-qa-reviewer.md` | 1715 LOC ≈ 43k Tokens |
| `appsec-stride-analyzer.md` | 581 LOC ≈ 16k Tokens |
| Fragment ↔ Producer ↔ Schema | Implizite Relation in mehreren Registries (`compose_threat_model.py`, `validate_fragment.py`, `qa_checks.py`, `sections-contract.yaml`), kein eigener Drift-Test |
| Drift-Guards | Substring-basiert, fangen keine semantische Drift |
| STRIDE-Coverage | LLM-probabilistisch, keine deterministische Faktenbasis |
| `eval()` mit restricted builtins | 2× (`compose_threat_model.py:382`, `qa_checks.py:1114`) — Regex-Vorfilter, Input heute plugin-shipped. Wird in **M10** durch deterministischen Pattern-Resolver ersetzt; `eval()` verlässt das Codebase komplett. |

---

## Empfohlene Sequenz

```
Kernplan (inhaltlich):    A0 (0.5–1d) → A1 (1–1.5d) → A2 (0.5–1d) → B1 Pilot (3–4d) → C1 (1d)
Parallel-Track (Phase D): M1 (1d) → M2 (0.5h) → M3a (15m) → M6 (1h)
                          → M7 (0.5h) → M4 (1–2h) → M8 (1h) → M9 (0.5h) → M3b (15m, später)
```

**Kernplan: 6–8 Tage**, verteilt auf 5–6 PRs.
**Phase D: ~2 Tage** verteilt auf 8 kleine PRs, größtenteils parallel und unabhängig zum Kernplan.

**B1 vollständig** bleibt sinnvoll, aber erst nach dem Pilot und nach Messdaten aus A0. Semgrep ist nach Verifikations-Pass **vollständig aus dem Plan entfernt** (siehe "Bewusst nicht im Plan").

Jede Phase ist eigenständig wertvoll. Stop nach Phase A, nach dem B1-Pilot oder nach Phase D ist möglich, ohne dass Vorarbeit verfällt.

---

## Phase A — Fundament + Baseline

### A0 — Mess-Baseline konsolidieren (vor allen Performance-Behauptungen)

**Aufwand:** 0,5–1 Tag
**Risiko:** niedrig

**Status (2026-05-29):** `scripts/measure_run.py` + `tests/test_measure_run.py` existieren und sind grün — der Consolidator faltet `.stage-stats.jsonl`, `verify_run_costs.py --json` (cumulative-safe) und `.hook-events.log`-Signale in ein `.run-metrics.json`. Verifizierter Bugfix: `_read_hook_events` matchte nur `reason=`, der reale Emitter (`agent_logger.py:1684`) schreibt aber `stop_reason=` → die Stop-Grund-Metrik war auf echten Logs **immer leer**. Parser auf `(?:stop_)?reason=` erweitert, Test-Fixture auf das reale Log-Format umgestellt. Capture-Runbook: `docs/baselines/README.md`. **Offen (manuell, kostet je einen Run):** die 2-Repo-Baseline tatsächlich aufnehmen und unter `docs/baselines/` einchecken.

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

**Sequenz zu M1 (Phase D):** A0 und M1 sind orthogonal — `ruff format`/Lint berührt nur `scripts/`/`tests/`/`hooks/`, nicht die Agent-`.md`-Files, die das LLM während Assessments liest. M1 ändert weder Tokens noch Cache-Hits noch Wall-Time messbar. Saubere Disziplin: A0-Baseline einmal auf Pre-M1-HEAD aufnehmen (= heute), nach M1-Merge **erneut** runnen ("Post-M1-Baseline"), und alle späteren Vergleiche (A2, B1) gegen die Post-M1-Variante fahren. Wenn Pre/Post-Differenz vernachlässigbar (erwartet), Pre-Snapshot verwerfen. Wenn Differenz signifikant: untersuchen, was M1 unbeabsichtigt geändert hat — diese Lücke will man früh sehen. Kosten: ein zusätzlicher Assessment-Run pro Test-Repo.

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

**Was:** `scripts/compose_threat_model.py` Zeilen 1146–1683 (7 `_read_*`-Funktionen + Helpers) → neues Modul `scripts/_manifest_readers.py`.

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
- **Wartbarkeit:** Blueprint für spätere Section-Renderer-Extraktion. `compose_threat_model.py` von 6989 → ~6451 LOC.
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

---

## Phase D — Querschnittliche Maßnahmen (Tooling, Doku, Konsolidierung)

**Aufwand gesamt:** ~2 Tage verteilt auf 8 kleine PRs
**Risiko:** niedrig bis null

Diese Maßnahmen sind nicht phasen-gegated wie A/B/C. Sie können größtenteils parallel und unabhängig laufen. Alle Befunde verifiziert gegen den Repo-State am 2026-05-12.

### Verifizierte Lücken (Befund)

| Befund | Verifizierte Realität |
|---|---|
| Kein Linter / Formatter | Keine `pyproject.toml`, kein `ruff.toml`, kein `.editorconfig`. 47k LOC Python, 67 Scripts ohne statische Analyse. |
| Kein pytest-Config | Keine `pytest.ini`, keine `[tool.pytest.ini_options]`. Nur Standard-Marker (`parametrize`, `skipif`) im Einsatz. |
| Coverage nicht in CI | `pytest-cov>=5` ist in `tests/requirements-test.txt`, aber CI ruft `pytest` ohne `--cov` auf → kein Baseline-Wert vorhanden. |
| 5 verschiedene YAML-Loader | `migrate_v3_to_v4`, `triage_compute_ranking`, `architect_structural_checks`, `slice_taxonomy`, `render_completion_summary` mit je unterschiedlicher Fehler-Semantik (raise vs. None vs. `{}` vs. caller-default vs. dict-type-check + import-fallback). |
| Fragment-Registry-Pfade nirgendwo zentral dokumentiert | 4 Maps verstreut über 3 Files. `AGENTS.md` Rule 4 hat den Workflow, aber nicht die konkreten Pfade. |
| Keine `docs/internal/runbooks/adding-a-section.md` Doku | Walkthrough für neue Sections fehlt komplett. |
| `CONTRIBUTING.md` (62 Zeilen) ohne Code-Style-Erwartung | Keine Erwähnung von Lint/Type-Hints/Pre-Commit. |

---

### M1 — `pyproject.toml` + ruff einführen

**Aufwand:** ~1 Tag (inkl. Cleanup-PR)
**Risiko:** niedrig

**Was:** Neue `pyproject.toml` mit ruff-Konfig, One-Shot-Cleanup-PR, CI-Step vor pytest.

**Konfig-Anker:**
```toml
[tool.ruff]
line-length = 120
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]

[tool.ruff.format]
quote-style = "double"
```

**Verifizierte Grundlagen:**
- `line-length = 120` → nur **56 Zeilen >120 Zeichen** in 47k LOC.
- `quote-style = "double"` matched **17283 von 18024** Strings (96%).
- `target-version = "py310"` matched die CI-Matrix (Python 3.10–3.12).

**Vorgehen:**
1. `pyproject.toml` anlegen (auch Heimat für M2).
2. One-Shot-Cleanup-PR: `ruff check --fix scripts/ tests/ hooks/` + `ruff format scripts/ tests/ hooks/`. **Diff manuell prüfen**, nicht blind mergen — insb. `UP`-Auto-Fixes (z.B. `Optional[X]` → `X | None`).
3. CI-Step in `.github/workflows/tests.yml` **vor** pytest:
   ```yaml
   - name: Lint (ruff)
     run: ruff check scripts/ tests/ hooks/
   - name: Format check (ruff)
     run: ruff format --check scripts/ tests/ hooks/
   ```

**Mehrwert:**
- **Wartbarkeit (Hauptgewinn):** Spürbar bei jedem PR. Aktuell hat ein 47k-LOC-Codebase keinerlei statische Analyse.
- **Qualität:** `F`/`B` fangen echte Bugs (ungenutzte Imports, mutable default args, suspicious patterns).
- **Performance:** Kein Effekt.

**Risiken:**
- Auto-Fix kann Semantik subtil ändern (selten, aber `UP`-Regel modernisiert Idiome). Mitigation: Cleanup-PR mit kleinem, lesbarem Diff splitten — eine Regel-Familie pro Commit.

**Erfolgskriterien:** `ruff check` clean, CI gate-d, Pull-Requests werden bei Verstößen rot.

---

### M2 — pytest-Konfiguration straffen

**Aufwand:** 30 Min
**Risiko:** niedrig

**Was:** In `pyproject.toml` aus M1:
```toml
[tool.pytest.ini_options]
addopts = "--strict-markers --strict-config"
filterwarnings = ["error::DeprecationWarning:scripts"]
```

**Verifizierte Grundlage:** Tests nutzen nur Standard-Marker (`parametrize`, `skipif`) → `--strict-markers` bricht nichts. `filterwarnings` ist auf `scripts/` gescoped → keine Library-Warnings.

**Risiken:** Latent DeprecationWarnings im Eigencode könnten CI rot machen. Mitigation: vorher lokal `pytest -W error::DeprecationWarning:scripts` laufen lassen.

---

### M3 — Coverage in zwei Schritten

**Aufwand:** je 15 Min (Schritt A jetzt, Schritt B nach ≥4 Wochen / 10 grünen Runs)
**Risiko:** null (Schritt A), niedrig (Schritt B)

**Was:**
- **Schritt A:** CI um `--cov=scripts --cov-report=term-missing` erweitern. **Kein** Fail-Under-Gate.
- **Schritt B:** Nach ausreichender Datenlage den niedrigsten gemessenen Wert als `--cov-fail-under=N` setzen — als Floor, nicht aspirational.

**Verifizierte Grundlage:** `pytest-cov>=5` ist bereits in `tests/requirements-test.txt`, CI ruft ihn aber nicht auf → kein Baseline-Wert verfügbar. 2-Stufen-Ansatz löst das Henne-Ei-Problem.

---

### M4 — YAML-Loader konsolidieren

**Aufwand:** 1–2 Std verteilt auf 5 Mini-PRs
**Risiko:** niedrig pro PR

**Was:** Neues Modul `scripts/_yaml_io.py` (getrennt von `_atomic_io.py` — Read/Write-Trennung):

```python
_RAISE = object()
def load_yaml(path: Path, *, default=_RAISE):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if default is _RAISE: raise
        return default
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        if default is _RAISE: raise
        return default
    return data
```

**Verifizierte Callsite-Migration** (5 Files, je eigene Semantik-Entscheidung):

| File | Aktuelle Semantik | Neuer Aufruf |
|---|---|---|
| `migrate_v3_to_v4.py` | raise auf Fehler | `load_yaml(p)` |
| `triage_compute_ranking.py` | caller-default | `load_yaml(path, default=default)` |
| `architect_structural_checks.py` | None auf Fehler | `load_yaml(path, default=None)` |
| `slice_taxonomy.py` | `{}` bei leer, str-Pfad | `load_yaml(Path(path), default={})` |
| `render_completion_summary.py` | `{}` + Dict-Type-Check + Import-Fallback | `load_yaml(path, default={})` + isinstance außerhalb |

**Risiken:** `render_completion_summary._load_yaml` hat einen defensiven `try: import yaml` mit `{}`-Fallback. Vor Migration klären, ob `yaml` wirklich überall Pflicht-Dependency ist (Hinweis: in `scripts/requirements.txt`). Falls historisch optional: dort lokalen Wrapper behalten, Helper trotzdem für die anderen 4 nutzen.

**Mehrwert:** Eine Quelle der Wahrheit für Default-Verhalten. Verhindert die nächste leise Divergenz.

---

### M6 — Modul-Karte in den zwei Monolithen

**Aufwand:** 1 Std
**Risiko:** null

**Was:** Existierende Module-Docstrings in `compose_threat_model.py` und `qa_checks.py` um einen Zeilennummern-Index ergänzen, z.B.:

```
Module map:
    L60–131    Exceptions & RenderContext
    L132–281   Helper utilities
    L282–367   eval_condition (sandboxed)
    L368–577   Jinja environment
    ...
    L1146–1683 Manifest readers (Phase A2 extraction target)
    ...
```

**Verifizierte Grundlage:** Beide Files haben bereits je ~30 `# -----` Section-Divider-Kommentare. Es fehlt nur die navigierbare Übersicht oben.

**Risiken:** Zeilennummern altern. Mitigation: grobe Ranges nennen ("L1100–1700") statt jeder Funktion einzeln. Optional als Folge-Schritt: kleines Generator-Skript.

---

### M7 — Fragment-Registry-Pfade in `schema-invariants.md` (§4f)

**Aufwand:** 30 Min
**Risiko:** null

**Was:** An `docs/internal/contracts/schema-invariants.md` neue Section §4f anhängen, die alle 4 Registry-Maps mit Datei + Zeile listet. In `AGENTS.md` Rule 4 Sub-Bullet auf §4f verweisen.

**Verifizierte Pfade:**
- `_SECTION_FRAGMENT_MAP` — `scripts/compose_threat_model.py:89`
- `_KNOWN_JSON_FRAGMENT_SCHEMAS` — `scripts/compose_threat_model.py:106`
- `FRAGMENT_SCHEMAS` — `scripts/validate_fragment.py:39`
- `_FRAGMENT_FILENAMES` — `scripts/validate_fragment.py:58`
- `CONTRACT_SECTION_FRAGMENTS` — `scripts/qa_checks.py:1131`

**Abhängigkeit:** Wenn A1 (Registry-Linter) umgesetzt wird, sollte §4f darauf verweisen. Falls A1 entfällt: §4f als rein-deskriptive Karte halten ohne Linter-Erwähnung.

---

### M10 — `eval_condition` → deterministischer Pattern-Resolver (eval() entfernen)

**Aufwand:** 1–2 Std
**Risiko:** null

**Was:** Beide `eval()`-Aufrufe (`compose_threat_model.py:382`, `qa_checks.py:1114`) durch einen 15-LOC Pattern-Resolver ersetzen, der nur drei explizite Muster akzeptiert. Kein `eval()` mehr im Codebase.

Aktuell schützt nur ein Regex-Vorfilter (`_COND_SAFE_TOKENS`) — der lässt z.B. `().__class__.__bases__[0].__subclasses__()` durch, weil alle Zeichen zur Whitelist gehören. Heute kein realer Exploit (Conditions kommen aus `data/sections-contract.yaml`, plugin-shipped), aber:

- Code ist nicht offensichtlich-korrekt: jeder Reviewer pausiert bei `eval(expr, {"__builtins__": {}}, …)` mit Regex-Sandbox.
- `SECURITY.md` dokumentiert aktuell "untrusted-repo mode" als geplant — diese Stelle wäre dort ein offener Footgun, falls Conditions je nutzerkonfigurierbar werden.

**Wirklich erreichbare Conditions** (Trace über alle 5 Call-Sites, verifiziert gegen `data/sections-contract.yaml` HEAD):

Ausschließlich bare-name Bool-Lookups aus `document.order[].condition`:
- `check_requirements`, `compose_warned`, `render_security_architecture`, `triage_has_warnings`
- `run_warned` (im YAML noch auskommentiert, Plan-relevant für M2.15)

Die Call-Site `compose_threat_model.py:1800` über `sub_sections[].conditional` ist heute unerreichbar, weil `threat_register.sub_sections: []` leer ist (`sections-contract.yaml:1033`). Der dortige Code-Kommentar spekuliert auf zukünftiges `low_category_count > 0` — der Migrationspfad ist ein abgeleiteter Bool im `eval_context` (`low_category_present = low_category_count > 0`), nicht numerische Arithmetik im YAML.

**Drei explizit unterstützte Muster** (decken die im YAML *dokumentierten* Patterns, nicht nur die heute aktiv eval'ten):

1. Bare Name → `bool(env.get(name))`
2. `not <name>` → `not bool(env.get(name))`
3. `<name> in [<items>]` / `<name> not in [<items>]` → Membership, bare Items werden zu impliziten String-Literalen

Numerische Vergleiche (`<`, `>`, `==`), `and`/`or`-Kombis und Funktionsaufrufe sind bewusst **nicht** unterstützt. Wer das braucht, muss den abgeleiteten Bool in `eval_context` ablegen — selbstdokumentierender und einfacher zu testen als YAML-Inline-Arithmetik.

**Deliverable:**

- Neues Modul `scripts/_safe_cond.py` mit `resolve_condition(expr: str, env: dict) -> bool` (~15 LOC, kein `eval`, kein `compile`, kein `ast`). Unbekannte Muster werfen `ContractError`.
- `compose_threat_model.py:364-384` ruft `_safe_cond.resolve_condition` und behält den `ContractError`-Wrapper für die existierende Fehler-Semantik. Die `eval_condition()`-Funktion bleibt als dünner Adapter, damit die 4 Call-Sites unverändert bleiben.
- `qa_checks.py:1106-1116` ruft denselben Helper. Bisheriger Duplikat-Code entfällt.
- `tests/test_safe_cond.py` mit:
  - **Positiv-Cases**: alle real vorkommenden bare-name Conditions aus `sections-contract.yaml` liefern korrekte Bool-Werte gegen ein realistisches `env`. Plus die im YAML dokumentierten Patterns `not X` und `X in [a, b]` (auch wenn sie aktuell nicht durch `eval_condition` laufen — Future-Proofing).
  - **Adversarial-Cases**: `().__class__.__bases__[0].__subclasses__()`, `__import__('os').system('id')`, `x.upper()`, `[x for x in range(10)]`, `lambda: 1`, `1+1` — alle müssen `ContractError` werfen.
  - **Edge-Cases**: leerer String, nur Whitespace, Syntax-Fehler, unbekannter Name (heute behandelt als `None` → bleibt so).

**Risiken:** Verhaltens-Drift bei Conditions, die die heutige `eval()`-Sandbox versehentlich anders interpretiert. Mitigation: Positiv-Cases gegen die aktuell im Repo vorkommenden Conditions, Drift wird sichtbar.

**Verifizierte Grundlage:**
- 4 Call-Sites in `compose_threat_model.py`: Zeilen 1728, 1800, 6056, 6061 (1800 heute unerreichbar wegen leerem `sub_sections`).
- 1 Call-Site in `qa_checks.py`: Zeile 1035 (über `_safe_eval_cond`).
- `eval_context`-Variablen-Inventar: `compose_threat_model.py:5969-6006`.
- Heutige Regex-Whitelist: `compose_threat_model.py:361`, `qa_checks.py:1110`.
- Vollständige Conditions-Liste (HEAD): `grep -hE "condition: " data/sections-contract.yaml` → 8 unique Strings, davon **nur** `check_requirements`, `compose_warned`, `render_security_architecture`, `triage_has_warnings` erreichen `eval_condition`.

**Empfohlener Folge-Cleanup (optionaler Side-PR, nicht Teil von M10):** Vier YAML-Felder entfernen, die wie Conditions aussehen, aber von `eval_condition` nicht erreicht werden:
- `intro_conditional.condition: "verdict_severity in [yellow, red]"` (`sections-contract.yaml:463`) — dieselbe Logik ist redundant hartcodiert in `compose_threat_model.py:3424`; das YAML-Feld wird nicht gelesen.
- `required_patterns_condition: "not skip_attack_walkthroughs"` (`sections-contract.yaml:657`) — Orphan-Feld, kein Python-Konsument auffindbar (`grep -r` im Repo, HEAD).
- `per_critical_subsection_condition: "not skip_attack_walkthroughs"` (`sections-contract.yaml:659`) — selbe Lage wie das vorige.
- `conditional: "len(changelog) > 0"` auf `changelog` section (`sections-contract.yaml:240`) — Section wird in `compose_threat_model.py:1726` über `if sid in ("infobox", "changelog", "toc"): continue` vorab geskippt; der Renderer hat seinen eigenen `if not changelog: return ""`-Pfad.

Diese Felder erwecken den Eindruck, das Plugin könne Operator-Vergleiche und `in [list]`-Patterns auswerten, obwohl sie in der heutigen Code-Realität tot sind. Cleanup macht die Contract-Datei selbstdokumentierend und passt zur strikten M10-Grammatik.

**Abhängigkeit:** keine. Kann parallel zu jedem anderen Phase-D-Item mergen.

---

### M8 — `docs/internal/runbooks/adding-a-section.md`

**Aufwand:** 1 Std
**Risiko:** null

**Was:** Neue Datei mit Schritt-für-Schritt-Walkthrough für eine neue Section in `threat-model.md`:
1. Deklaration in `data/sections-contract.yaml`.
2. Falls `fragment_type ∈ {data, hybrid}`: Schema in `schemas/fragments/<id>.schema.json` + alle 4 Registries (Link auf §4f aus M7).
3. Renderer-Funktion in `compose_threat_model.py`.
4. Test in `tests/test_compose_threat_model.py`.
5. Anchor-Linkifier in `qa_checks.py:linkify_anchors`, falls neue ID-Klasse — siehe `schema-invariants.md` §4a.

**Risiken:** Doku altert mit dem Code. Mitigation: kurz halten, vor allem Pfade nennen; Details bleiben in den Quellen.

---

### M9 — `CONTRIBUTING.md` erweitern

**Aufwand:** 30 Min
**Risiko:** null, aber sequenz-gebunden

**Was:** Drei neue Sections:
- `## Code style` — verweist auf `ruff check` / `ruff format` (M1)
- `## Adding components` — verlinkt M7 (`schema-invariants.md` §4f) und M8 (`adding-a-section.md`)
- `## Type hints` — "New public functions take type hints; mypy is not yet enforced"

**Abhängigkeit:** Darf **nicht** vor M1+M7+M8 mergen, sonst stehen tote Verweise im Dokument.

---

### Phase-D-Reihenfolge

| # | Maßnahme | Aufwand | Abhängigkeit |
|---|---|---|---|
| 1 | M1 ruff + pyproject.toml | 1 Tag | — |
| 2 | M2 pytest strikt | 30 Min | M1 (Heimat) |
| 3 | M3a Coverage in CI ohne Gate | 15 Min | — |
| 4 | M6 Modul-Karte | 1 Std | — |
| 5 | M7 §4f Registry-Pfade | 30 Min | optional A1-Verweis |
| 6 | M10 `eval_condition` → Pattern-Resolver | 1–2 Std | — |
| 7 | M4 YAML-Loader (5 Mini-PRs) | 1–2 Std | — |
| 8 | M8 adding-a-section.md | 1 Std | M7 |
| 9 | M9 CONTRIBUTING.md | 30 Min | M1, M7, M8 |
| 10 | M3b Coverage-Floor | 15 Min | M3a + ≥4 Wochen |

**Gesamt: ~2 Tage + 1–2 h** ohne Wartezeit für M3b. Größter Einzelposten ist M1 (~50% der Phase).

---

## Bewusst nicht im Plan

| Item | Begründung |
|---|---|
| `from __future__ import annotations` flächendeckend | Ehemals M5. Die 5 betroffenen Scripts (`agent_logger.py`, `harvest-requirements.py`, `security_steering.py`, `slice_taxonomy.py`, `mock-server.py`) nutzen kein `get_type_hints` / Pydantic / `@dataclass` — Annotation-Lazifizierung ist semantisch leer. Konsistenz-Theater ohne verifizierbaren Nutzen. Falls ein zukünftiger Script-Touch tatsächlich Introspection einführt, dort lokal nachziehen. |
| `qa_checks.py` splitten | Hohe Kopplung (geteilter Regex/Label-Index-State), hohes Refactoring-Risiko. Erst nach Phase B angehen, wenn man eingespielt ist. |
| Semgrep (jede Variante) | Aus dem Plan komplett entfernt. Pinned-Ruleset verliert den Semgrep-Mehrwert (aktuelle Rules); advisory-only-Modus ist instabil unter Druck; Ownership für Ruleset-Pflege ungeklärt; "Auditierbarkeit" hat günstigere Lösungen (strukturierte Evidence-Felder im LLM-Output). |
| Prompts → YAML/Code | Radikal, ungetestet. Erst nach B1 mit Prototyp evaluieren. |
| Semantische LLM-as-Judge-Drift-Tests | Cost-intensiv. Erst nach B1 sinnvoll. |
| `mypy` einführen | 47k LOC ohne prior Typdisziplin → wochenlange `Any`-Aufräumung. Nicht low-risk. Falls überhaupt: nach Phase D auf einem kleinen Modul prototypen. |
| Pre-Commit-Hooks | Erst sinnvoll, wenn ruff im CI ist (M1). Sonst kämpfen lokale Hooks gegen drifting Konfig. Phase 2 von Tooling. |
| Scripts in ein Package ziehen (`scripts/__init__.py`) | Import-Path-Migration für 67 Files + 92 Test-Files. Hohes Churn-Risiko, niedriger Tagesnutzen. |
| Dash-Scripts umbenennen (`harvest-requirements.py`, `mock-server.py`) | Nicht als Python-Modul importierbar, aber Umbenennung würde Caller brechen. Code-Smell, nicht-blocker. |

---

## Erwartete Effekte

| Metrik | Baseline (A0 misst) | Nach Plan | Quelle des Gewinns |
|---|---|---|---|
| LOC im größten File | 6989 (`compose_threat_model.py`) | ~6451 | A2 |
| LOC im größten Prompt-File | 2009 (`phase-group-finalization.md`) | ≤800 pro Sub-File | B1 |
| Tokens in Phase 11 | ~44k | ~25–30k aktiver Kontext | B1 |
| Kontext-Fenster-Headroom | abnehmend | +30–40k Tokens | B1 |
| Token-Kosten pro Run | Baseline | **nicht vorab zusagen**; erwartbar eher einstellige % ohne weitere STRIDE-Änderungen | B1, falls selektives Laden tatsächlich greift |
| Wall-Time pro Run | Baseline | **nicht vorab zusagen**; nur messen | A0 + B1 |
| Drift-Detection im CI | Substring | Strukturell + Token-Bounds | C1 |
| Statische Analyse | nicht vorhanden | ruff lint + format als CI-Gate | M1 |
| Coverage-Sichtbarkeit | nicht in CI gemessen | `--cov` in CI, Floor-Wert nach 4 Wochen | M3 |
| Registry-Drift-Sichtbarkeit | implizit über 4 Maps | dokumentiert in §4f + maschinell prüfbar via A1 | M7 + A1 |
| Onboarding-Doku | Workflow ohne konkrete Pfade | `adding-a-section.md` + erweiterte `CONTRIBUTING.md` | M8 + M9 |

**Wichtig:** Performance-Effekte sind Hypothesen. A0 misst sie. Wenn Realität von Schätzung abweicht: dokumentieren und Plan anpassen, nicht ignorieren.

---

## Wartbarkeits-Skala (verifiziert)

| Stand | Skala 1–10 |
|---|---|
| Heute | ~5,5 |
| Nach Phase D (Tooling/Doku/Konsolidierung) | ~6–6,5 |
| Nach Phase D + Phase A (A0+A1+A2) | ~6,5–7 |
| Nach Phase D + B1 | ~7,5 |
| Nach Phase D + B1 + C1 | ~7,5–8 |

Delta: ~2–2,5 Punkte über den vollen Plan. Größter Einzelsprung kommt nicht aus B1, sondern aus dem Zusammenspiel von **M1 (Lint-Gate) + A1 (Registry-Linter) + M7 (Registry-Doku)** — danach sind die zwei häufigsten stillen Defekt-Quellen (Style-Drift, Registry-Drift) maschinell gegated.

Die Skalen-Zahlen sind Hausnummern und sollten nicht überinterpretiert werden.

---

## Offene Fragen vor Start

1. **Sind Golden-Output-Tests politisch akzeptabel?** B1 hängt davon ab. Falls Test-Lauf-Kosten ein Problem sind, gibt es alternative Verifikationsstrategien (Diff auf Strukturebene statt Full-Output).
2. **Welche zwei Repos sind die "kanonischen" Test-Cases?** Juice Shop ist offensichtlich, das zweite muss gewählt werden — idealerweise ein Repo mit unterschiedlichem Profil (z.B. Python statt JS, Microservices statt Monolith).
3. **Soll B2 (QA-Reviewer) jemals nachgezogen werden?** Falls Repair-Loops in der Praxis Budget exhausten, ja. Sonst dauerhaft verschieben.
4. ~~**Wer editiert Phase-Prompts in der Praxis — Menschen oder primär Claude?**~~ **Beantwortet 2026-05-12.** Git-Historie zu `agents/phases/phase-group-*.md`: ein Author (Matthias Rohr), `Co-Authored-By: Claude` in 5 von ~40 Commits (alle aus jüngeren M3.4-Sprints mit substanziellem Logik-Refactor). Commit-Größen-Profil: überwiegend 1–100 LOC, gelegentlich 100–200 LOC. Verhältnis grob ~85% Mensch / ~15% Claude-assistiert. → **B1-Maintainability-ROI bestätigt**: das Argument "Menschen lesen 400 LOC leichter als 2009 LOC" greift hier; B1 ist freigabefähig als Wartbarkeits-Investition (Performance-Effekt weiterhin nur nach A0-Messung behaupten).

---

## Quellenangaben (verifiziert während Plan-Erstellung und Update)

**Kernplan (A/B/C):**
- Lazy-Load-Mechanismus: `agents/appsec-threat-analyst.md:202, 245, 388-432`
- Drift-Guard-Stil: `tests/test_dispatch_prompt_cache_order.py` (substring-asserts), `tests/test_agent_definitions.py` (Frontmatter-Validation, 23 Tests)
- Phase-Group-Struktur: `agents/phases/phase-group-finalization.md` (51 Subheadings: 10× `##` + 46× `###` + 5× `####`; 2009 LOC)
- Budget-Exhaustion-Vorfall: `tests/test_agent_definitions.py:24-28` (Kommentar zur 75→120-Turn-Erhöhung)
- Fragment-Registry-Lücke: `data/sections-contract.yaml` (11 Fragmente deklariert) vs. `schemas/fragments/` (7 Schemas) — Unterschied legitim wegen `fragment_type: markdown`/`computed`, aber **kein** automatischer Cross-Check vorhanden.
- Fragment-Registry-Realität: `compose_threat_model.py`, `validate_fragment.py`, `qa_checks.py` und `sections-contract.yaml` enthalten mehrere überlappende Maps. `compose_threat_model.py:84` verweist im Kommentar auf `tests/test_qa_fragment_map.py`, die Datei existiert aktuell nicht.
- Stage-2-Renderer: `agents/appsec-threat-renderer.md` ist bereits schlank und lädt nicht den ganzen Finalization-Prompt; B1 ist daher primär Wartbarkeit, nicht garantiert Performance.
- Messpfade: `record_stage_stats.py`, `verify_run_costs.py`, `cost_running_total.py`, `.stage-stats.jsonl`, `.hook-events.log`, `SESSION_STOP`, `ASSESSMENT_TOKENS`.
- `eval()`-Stellen: `scripts/compose_threat_model.py:382`, `scripts/qa_checks.py:1114`
- Monolith-Größen: gemessen via `wc -l` — `compose_threat_model.py` 6989, `qa_checks.py` 5212, `validate_fragment.py` 317
- Token-Schätzungen: bytes/4 als Approximation

**Phase D (Tooling/Doku/Konsolidierung):**
- Keine Linter-Konfig: Existenz-Check über `pyproject.toml`, `ruff.toml`, `.ruff.toml`, `setup.cfg`, `.editorconfig` — alle fehlen.
- Quote-Style: `grep` über `scripts/*.py` ergibt 17283 double-quoted vs. 741 single-quoted Strings.
- Zeilen-Längen: `awk 'length>120'` → 56 Zeilen, `length>100` → 288 Zeilen in 47k LOC `scripts/`.
- pytest-Marker: nur `parametrize` und `skipif` aus `grep "@pytest.mark\." tests/`.
- pytest-cov-Verfügbarkeit: `tests/requirements-test.txt` enthält `pytest-cov>=5.0`. CI-Workflow `.github/workflows/tests.yml` ruft `pytest tests/ -v --tb=short` ohne `--cov`.
- YAML-Loader-Inventar: 5 Treffer für `^def _?load_yaml\b` in `scripts/`, jeder mit unterschiedlicher Signatur und Fehler-Semantik.
- Registry-Pfade (`M7`): grep-verifiziert auf `_SECTION_FRAGMENT_MAP` (compose:89), `_KNOWN_JSON_FRAGMENT_SCHEMAS` (compose:106), `FRAGMENT_SCHEMAS` (validate_fragment:39), `_FRAGMENT_FILENAMES` (validate_fragment:58), `CONTRACT_SECTION_FRAGMENTS` (qa_checks:1131).
- Doku-Lücke `adding-a-section.md`: `find docs -iname "*adding*"` → keine Treffer.
- `CONTRIBUTING.md` Inhalt: 62 Zeilen, Sections "Commands", "Repository layout", "Agent definition format", "Reporting security issues" — keine Code-Style-Erwartung.
- `AGENTS.md` Rule 4 deckt den abstrakten Workflow ab (`schema → producer → consumer → validation → tests`), nicht aber die konkreten Registry-Pfade.

---

**Dieser Plan ist ein Vorschlag. Vor Umsetzung: Diskussion + Priorisierung im Team. Insbesondere die noch Offenen Fragen 1–3 klären (Frage 4 ist seit 2026-05-12 beantwortet).**
