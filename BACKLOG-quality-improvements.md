# Quality Improvement Backlog

Generated: 2026-04-09
Context: Comprehensive quality analysis of the appsec-plugin

## Status Legend

- [ ] Open
- [x] Done (implemented 2026-04-09)

---

## Completed (Sofort-Maßnahmen)

- [x] **C-2:** Requirement-Threat-Candidate-Format vereinheitlicht (Singular statt Plural in `phase-group-architecture.md`)
- [x] **C-4:** QA-Reviewer maxTurns von 45 auf 55 erhöht (`appsec-qa-reviewer.md`, `test_agent_definitions.py`)
- [x] **H-2:** Config dreifach-Laden refactored zu `_load_config()` Cache (`agent_logger.py`)
- [x] **H-3:** Atomic Writes für Session-Agent-Mapping (`agent_logger.py` — `tempfile` + `os.replace`)
- [x] **H-5:** `Bash(*)` auf explizite Command-Allowlist eingeschränkt (`settings.json`)

---

## Nächster Sprint — High Impact

### C-1: Logging-Boilerplate in Shared-Datei extrahieren
**Priority:** Critical | **Effort:** Medium | **Impact:** ~200 Zeilen Redundanz eliminiert, 1 Turn/Agent gespart

**Dateien:** Alle 5 Sub-Agenten (`context-resolver`, `recon-scanner`, `dep-scanner`, `stride-analyzer`, `qa-reviewer`)

**Problem:** Identische ~40-Zeilen Logging-Sections in jedem Agent (AGENT_START, STEP_START/END, FILE_WRITE, AGENT_END Templates).

**Lösung:**
1. Neue Datei `agents/shared/logging-standard.md` mit dem kanonischen Logging-Template (parametrisiert nach Agent-Name)
2. In jedem Agent ersetzen durch: `Follow logging standard from shared/logging-standard.md (agent name: <NAME>, model: <MODEL>)`
3. Nur agent-spezifische Abweichungen (z.B. QA-Reviewer CHECK_START/CHECK_END) verbleiben inline

---

### C-3: Phase-Group vs. Orchestrator Autoritätsregel klären
**Priority:** Critical | **Effort:** High | **Impact:** ~300 Zeilen redundanten Orchestrator-Content reduzierbar

**Dateien:** `appsec-threat-analyst.md:133-138`, alle Phase-Group-Dateien

**Problem:** Orchestrator enthält detaillierte Inline-Instruktionen UND liest Phase-Groups. Keine Regel welche bei Widersprüchen gilt.

**Lösung:**
1. In `appsec-threat-analyst.md` klarstellen: "Phase-group files are the **authoritative** source. Orchestrator inline instructions provide context and parameter lists only."
2. Redundante Inline-Instruktionen im Orchestrator auf Verweise reduzieren (z.B. Phase 8 Grep-Patterns → nur in Phase-Group, Orchestrator sagt "see phase-group")
3. Alternativ: Phase-Groups als einzige Quelle, Orchestrator enthält nur Ablauflogik und Parameter

---

### H-1: Phase 2 → Phase 8 Ergebnisse wiederverwenden
**Priority:** High | **Effort:** Medium | **Impact:** 5-10 Orchestrator-Turns gespart

**Dateien:** `phase-group-architecture.md:77`, `appsec-threat-analyst.md` Phase 8

**Problem:** Phase 8 sagt "do not rely on Phase 2 memory — actively search". Aber Phase 2 (Recon-Scanner) hat bereits 12 Security-Kategorien durchsucht und in `.recon-summary.md` geschrieben.

**Lösung:** Phase 8 ändern zu: "**Validate and extend** Phase 2 findings from `.recon-summary.md` Section 7. Use Phase 2 results as starting point; verify with additional grep patterns and rate each control's effectiveness."

---

### H-7: Management Summary Ownership klären
**Priority:** High | **Effort:** Low | **Impact:** Konsistenz

**Dateien:** `phase-group-threats.md:101-141`, `phase-group-finalization.md`

**Problem:** Unklar ob Phase 9 den Summary baut oder Phase 11 ihn rendert.

**Lösung:** In `phase-group-threats.md` klarstellen: "Phase 9 assembles the data (findings list, mitigations list, ratings). Phase 11 renders the Management Summary section using Phase 9 data."

---

### H-8: Tests für `run-headless.sh` erstellen
**Priority:** High | **Effort:** Medium | **Impact:** 287 Zeilen Shell-Script, null Coverage

**Datei:** `scripts/run-headless.sh` (43 Conditional Branches)

**Lösung:** `tests/test_run_headless.sh` oder pytest mit `subprocess.run` für:
- Deprecated-Flag-Handling (--with-requirements → --requirements)
- URL-Parsing und Validierung
- Directory-Creation-Logik
- Model-Override-Passing
- Skill-Selection (create-threat-model vs check-appsec-requirements)

---

## Mittelfristig — Medium Severity

### M-1: Phase 8 im Phase-Group zu vage
**Effort:** Low

`phase-group-architecture.md:75-80` — nur 6 Zeilen vs. 54 im Orchestrator. Entweder auf gleiche Detailtiefe bringen oder explizit auf Orchestrator verweisen: "See orchestrator for full grep patterns and fail conditions."

---

### M-2: Logging-Bash-Commands in Phase-Groups dupliziert
**Effort:** Low (löst sich mit C-1)

`phase-group-recon.md:22-61` — 23 Zeilen Logging-Commands die auch im Orchestrator stehen. In Shared-Logging-Datei auslagern.

---

### M-3: `agent_logger.py` — Silent JSON Parse Error
**Effort:** Low

`agent_logger.py:656-678` — `except Exception: return` maskiert fehlerhafte JSON-Eingaben.

**Fix:** `sys.stderr.write(f"[appsec-logger] JSON parse error: {e}\n")` vor `return`.

---

### M-4: `agent_logger.py` — 15× bare `except Exception: pass`
**Effort:** Low

Überall in `agent_logger.py` — maskiert legitime Fehler (Disk full, Permissions).

**Fix:** `if _VERBOSE: sys.stderr.write(f"[appsec-logger] {type(e).__name__}: {e}\n")` vor `pass`.

---

### M-5: Phase 10 SCA Retry-Logik underdefiniert
**Effort:** Low

`phase-group-threats.md:143-150` — "Validate, retry once if invalid" ohne Details. Phase 9 hat ausführliche Retry-Logik.

**Fix:** Gleiche Retry-Pattern wie Phase 9 STRIDE-Analyzers verwenden.

---

### M-6: Section-Intro-Sätze — Timing unklar
**Effort:** Low

`phase-group-architecture.md:7-22` — Intro-Beispiele stehen bei Phase 3, werden aber erst beim Output-Writing (Phase 11) geschrieben.

**Fix:** Verschieben nach Phase 11 oder klarstellen: "Write introductory sentences during output generation in Phase 11, not during analysis phases."

---

### M-7: Test-Checkpoint-Pattern übersprungen
**Effort:** Low

`test_integration.py:307` — `INTERMEDIATE_PATTERNS[:-1]` schließt `.appsec-checkpoint` aus mit Kommentar "is new".

**Fix:** Entweder Test aktivieren (Feature ist stabil) oder Kommentar aktualisieren warum es übersprungen wird.

---

### M-8: CLAUDE.md Intermediate Files Table unvollständig
**Effort:** Low

`plugin/CLAUDE.md:177-189` — fehlt: `.requirements.yaml`, `.session-agent-map`, Log-Rotation (`.agent-run.log.1/.2`), `.hook-events.log`.

---

### M-9: Skill Argument-Parsing komplex
**Effort:** Medium

`create-threat-model/SKILL.md:8-71` — 63 Zeilen verteilt auf Flag-Parsing, Conflict-Detection, Requirements-Resolution, Path-Resolution.

**Fix:** In 3 klare Schritte konsolidieren: 1. Parse all flags, 2. Resolve conflicts and validate, 3. Resolve paths.

---

### M-10: Secret-Masking-Anweisung dupliziert
**Effort:** Low

`appsec-recon-scanner.md:159-177` — allgemeine Secret-Masking-Regel UND Category-12-spezifische Regel.

**Fix:** Zu einer einzigen Anweisung bei Category 12 zusammenführen.

---

## Langfristig — Low Severity

### L-1: Phase-Group Turn-Budget-Guidance dupliziert
`phase-group-threats.md:21-24` + `appsec-threat-analyst.md:602-606` — identische Tabelle. Nur an einer Stelle definieren.

### L-2: STRIDE-Dispatch-Parameter dupliziert
`phase-group-threats.md:15-19` + `appsec-threat-analyst.md:610-624` — 11 Parameter jeweils aufgelistet. Einmal definieren, einmal referenzieren.

### L-3: Section-Intro-Beispiele zu lang
`phase-group-architecture.md:9-21` — 12 Beispiele auf 15 Zeilen. 3 Beispiele + 1 Satz genügen.

### L-4: OWASP-Coverage-Check dupliziert
`phase-group-threats.md:40-46` fasst zusammen was der Orchestrator auf 60+ Zeilen detailliert. Nur an einer Stelle definieren.

### L-5: Config-Dateien ohne Inline-Kommentare
`config.json` und `check-appsec-requirements/config.json` — keine Hinweise was Felder bedeuten.

### L-6: Test-Redundanz maxTurns
`test_agent_definitions.py` — `test_max_turns_is_positive_integer` + `test_max_turns_does_not_exceed_ceiling` partiell redundant.

### L-7: Security-Steering-Tests mit Hardcoded Keywords
`test_security_steering.py` — Keywords hardcoded statt aus `steering_keywords.json` geladen. Tests brechen nicht wenn Config geändert wird.

### L-8: Inconsistente Output-Dateinamen
`check-appsec-requirements/SKILL.md` — `appsec-requirements-report.*` vs. `appsec-requirements-fallback.yaml`.

### L-9: `run-headless.sh` URL-Detection fragil
Zeile 129: `grep -qE '^https?://'` matched nicht `file://` URLs korrekt.

---

## Architektur-Verbesserungen (Diskussion)

### STRIDE-Analyzer Evidence-Verification verbessern
"grep finds nothing = absence confirmed" ist unzureichend. Sollte mindestens 1 confirmatory Code-Read erfordern.

### Recon-Scanner Category 13 (LLM Detection) aufteilen
Aktuell müssen ALLE 5 Patterns matchen (AND-Verknüpfung). Aufteilen in 4 Sub-Kategorien (SDK, Prompts, Vectors, Tools) mit OR-Verknüpfung für genauere Detection.

### Recon-Scanner Dangerous-Sinks-Patterns verfeinern
Category 8 flaggt `subprocess` und `eval` unabhängig vom Kontext. Patterns sollten User-Input-Proximity berücksichtigen.

### QA-Reviewer Section 2 Numbering Check korrigieren
Check 7 prüft auf Lücken in 2.1-2.5, aber verschiedene Complexity Tiers haben unterschiedliche erwartete Ranges (Simple: 2.1-2.3, Moderate: 2.1-2.4, Complex: 2.1-2.5).

### Requirements-Lookup vom STRIDE-Analyzer zum Orchestrator verschieben
Aktuell sucht jeder STRIDE-Analyzer in `.requirements.yaml` nach Requirement-Matches. Besser: Orchestrator pre-computed ein Lookup-Table in Phase 8b und übergibt es den Analyzern.

### Cache-Expiry für Requirements
`.cache/requirements.yaml` hat keinen Timestamp. Veraltete Requirements werden unbegrenzt wiederverwendet.
