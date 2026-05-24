# Parallelization Plan — Phase 2.5

**Stand:** 2026-05-24
**Scope:** Ein verifizierter Hebel zur Reduktion der Wall-Clock-Zeit der `create-threat-model`-Pipeline ohne Qualitätsverlust.
**Out of scope:** Modell-Downgrades (z. B. STRIDE auf Haiku), Architekt-Reviewer-Vorziehen (geprüft, abgelehnt — Post-Render-Coherence-Gate ist semantisch notwendig), STRIDE-Tail-Pod-Optimierung via FOCUS_PATHS (vertagt — siehe "Vertagt" unten).

---

## Pipeline-Baseline (verifiziert)

| Phase | Agent | Modell | Turns (Standard) | Sequenz heute |
|---|---|---|---|---|
| 1 | context-resolver | Haiku | 25 | parallel zu 2 |
| 2 | recon-scanner | Haiku | 25 | parallel zu 1 |
| 2 (+) | dep-scanner | n/a (Python) | — | parallel zu 1+2 wenn `WITH_SCA=true` |
| **2.5** | **config-scanner** | **Haiku** | **15** | **sequentiell nach 2** ← Hebel #1 |
| 2.6 | route_inventory.py / arch-coverage | n/a (Python) | — | nach 2.5 |
| 3–8 | threat-analyst (orchestrator) | Sonnet | — | sequentiell |
| 9 | stride-analyzer × N | Sonnet | 35/Pod | parallel, Wall-Clock = max() pro Pod |
| 10 | threat-merger | Opus@cheap | 12 | sequentiell |
| 10a | evidence-verifier | Haiku | 30 | sequentiell |
| 10b | triage-validator | Sonnet | 20 | sequentiell |
| 11 | threat-renderer | Sonnet | 80 | sequentiell |
| 12 | architect-reviewer (--architect-review) | Sonnet/Opus | 40 | sequentiell post-render |
| QA | qa-reviewer | Haiku | 120 | sequentiell post-render |

---

## Hebel #1 — Phase 2.5 (config-scanner) parallel zu Phase 1+2

### Status quo

`agents/phases/phase-group-recon.md:178`:
> *"After Phase 2 (recon-scanner) returns and `.recon-summary.md` is on disk, dispatch the config-scanner if any IaC/CI surface exists."*

`agents/phases/phase-group-recon.md:227-228`:
> *"**→ TOOL CALL REQUIRED (sequential, NOT parallel — Phase 2.5 needs Phase 2's recon-summary as input baseline):**"*

### Befund: Sequentialitäts-Begründung ist falsch

`agents/appsec-config-scanner.md:26-31` listet die tatsächlichen Inputs des Agents verbatim:

> ```
> ## Inputs (from orchestrator prompt)
> - REPO_ROOT — absolute path to the repository root
> - OUTPUT_DIR — absolute path to output directory
> - CLAUDE_PLUGIN_ROOT — plugin root
> - ASSESSMENT_DEPTH — quick / standard / thorough
> ```

`agents/appsec-config-scanner.md:35-71` ("Process") liest:
- `$CLAUDE_PLUGIN_ROOT/data/config-iac-checks.yaml` (statischer Plugin-Datafile)
- Direkte Globs auf `Dockerfile`, `.github/workflows/*`, `docker-compose*.yml`, `.github/dependabot.*`, `renovate.*`, `.npmrc`, `package.json` (Filesystem direkt)

**`.recon-summary.md` wird vom Config-Scanner-Agent nicht gelesen.** Die Sequentialitäts-Notiz in `phase-group-recon.md:227-228` ist veraltete Dokumentation, kein realer Constraint.

### Vorbedingungen (vor Plan-Umsetzung zu klären)

#### P1 — Config-Scanner-Modell-Drift auflösen

Vor jedem Edit an `phase-group-recon.md`: konfliktierende Modell-Pins eindeutig setzen. Heute:
- `AGENTS.md:215` → "appsec-config-scanner | **Haiku** | Always, every depth and reasoning tier"
- `phase-group-recon.md` Dispatch-Block → `model: $CONFIG_SCANNER_MODEL` **defaults to `claude-sonnet-4-6`**
- `SKILL-impl.md:2305` → `CONFIG_SCANNER_MODEL=<model>` default `claude-sonnet-4-6`

Sonst zementiert Schritt 4 (Doku-Redaktion) die falsche Variante. Eigener Bug-Fix-Commit vor Hebel #1.

### Implementierungsplan

#### Schritt 1 — Pre-Check früh ausführen

Der `HAS_IAC_SURFACE`-Bash-Block (`phase-group-recon.md:191-204`) ist ein reiner `compgen`-Filesystem-Check, kein Recon-Output-Verbraucher. Diesen Block in den Orchestrator vor den Phase-1+2-Dispatch ziehen (`agents/appsec-threat-analyst.md` → "Phases 1–2: Reconnaissance & Context (parallel dispatch)"-Block).

Wenn `HAS_IAC_SURFACE=false`: Stub-File (`{"parse_error": "skipped: no IaC surface detected", "findings": []}`) sofort schreiben, kein Dispatch — wie heute.

**Cold-Cache-Hinweis (R5):** Heute läuft der `compgen`-Block nach Phase 2 → Filesystem-Cache durch Recon-Scanner warm. Bei Frühausführung cold cache + 13 rekursive Globs (`**/`) → potenziell mehrere hundert ms auf Monorepos. Im Smoke-Test Zeitstempel `start_of_turn → end_of_HAS_IAC_check` loggen.

#### Schritt 1b — `CONFIG_SCANNER_MODEL` in Pre-Phase resolven (R6)

`RECON_SCANNER_MODEL` und `CONTEXT_RESOLVER_MODEL` werden heute in der Pre-Phase aus `.skill-config.json` gelesen, sodass sie beim Parallel-Dispatch verfügbar sind. `CONFIG_SCANNER_MODEL` wird heute erst im (sequentiellen) Phase-2.5-Dispatch-Block resolved. Vor Parallelisierung muss die Resolution in dieselbe Pre-Phase-Bash-Batch wandern — sonst fehlt die Variable beim Dispatch-Turn.

Verifikation: `grep -n 'CONFIG_SCANNER_MODEL\\|RECON_SCANNER_MODEL' agents/appsec-threat-analyst.md` — die beiden müssen am selben Codepfad gesetzt werden.

#### Schritt 2 — Dispatch-Block erweitern auf bis zu 3 Background-Agents

Aktueller Dispatch-Block (`phase-group-recon.md`, "Phase 1 + 2: Parallel Dispatch"):
- `context-resolver` mit `run_in_background: true` (wenn nicht cache-hit)
- `recon-scanner` mit `run_in_background: true` (wenn nicht fingerprint-skip)
- (optional) `dep-scanner` als Hintergrund-Python-PID (bleibt **nach** Recon — braucht `$MANIFESTS` aus `.recon-summary.md`)

Nach Änderung:
- **+ `config-scanner`** (wenn `HAS_IAC_SURFACE=true`)
- Dispatch in einer einzigen Orchestrator-Turn (alle Agent-Tool-Calls im selben Message-Block)
- `run_in_background` pro Agent: `true`, **außer wenn nur ein einziger Agent dispatched wird** (analog `phase-group-recon.md:13`: *"`true` (or `false` if only one is dispatched — the idle one can skip)"*)

**State-Matrix (R4) — vollständige Enumeration:**

| CTX_SKIP | RECON_SKIP | HAS_IAC | dispatched Agents | `run_in_background` |
|---|---|---|---|---|
| false | false | true | context + recon + config | alle `true` |
| false | false | false | context + recon | beide `true` |
| true | false | true | recon + config | beide `true` |
| true | false | false | recon allein | `false` |
| false | true | true | context + config | beide `true` |
| false | true | false | context allein | `false` |
| true | true | true | config allein | `false` |
| true | true | false | keine — Sprung zu Phase 3 | n/a |

Die heutige Dispatch-Logik löst nur 2 Variablen (CTX × RECON). Plan-Umsetzung muss explizit auf 3 Variablen erweitern. **dep-scan-Launch-Pfad unverändert** — bleibt post-Recon-Return wegen Manifest-Abhängigkeit. Auf keinen Fall in die Parallel-Batch ziehen.

#### Schritt 3 — Wait-Gate über Agent-Return, NICHT File-Polling (R2)

`phase-group-recon.md:14` ist die Truth-Source für den Wait-Mechanismus:
> *"Wait for BOTH background agents to return before proceeding to Phase 3 [...] do NOT check `.recon-summary.md` at that point and do NOT re-dispatch"*

Mechanismus = **Claude Code wartet implizit auf Agent-Tool-Returns aller `run_in_background:true`-Calls**. Kein File-Polling.

Erweiterung für Phase 2.5:
- Bestehender Wait-Block wird auf "wait for all 3 (or 2 / 1) returns" erweitert — keine separate Polling-Schleife für `.config-scan-findings.json`
- Validation (`validate_intermediate.py config_scan_findings`) läuft **nach** Agent-Return, vor Phase 2.6-Dispatch
- Failure-Handling unverändert (Stub schreiben, `AGENT_ERROR` loggen, weiterlaufen)
- dep-scan-PID wird wie heute erst bei Phase 10 `wait`-ed (kein Vorziehen)

#### Schritt 4 — `phase-group-recon.md` redigieren

- Zeile 178 (`"After Phase 2 returns and .recon-summary.md is on disk"`) → "In parallel with Phases 1 and 2 (no recon dependency)"
- Zeile 227-228 (`"sequential, NOT parallel — Phase 2.5 needs Phase 2's recon-summary"`) → "parallel with Phases 1 and 2; runs as background agent and is gated only at Phase 2.6"
- `run_in_background: false` → `true` (Zeile 232), mit Single-Agent-Exception aus Schritt 2

#### Schritt 5 — Logging: `.agent-run.log` UND `stage-stats.jsonl`

**5a. `AGENT_INVOKE` für config-scanner** mit den anderen beiden in **einem** Bash-Batch emittieren (nicht in eigener Turn). `AGENT_DONE` wird wie heute nach Validation gelogt.

**5b. `PHASE_START` / `PHASE_END` für Phase 2.5 mit Parallel-Suffix (R1).**

`phase-group-finalization.md:1142` ist die Truth-Source für die Aggregator-Semantik:
> *"For phases that ran in parallel (same PHASE_START timestamp), show the wall-clock duration of the parallel group for each phase row"*

Phase 1 macht das heute explizit (`phase-group-recon.md:34`):
```
PHASE_END   [Phase 1/11] Context Resolution complete (parallel with Phase 2)
```

Für Phase 2.5 analog:
- `PHASE_START [Phase 2.5/N]` **im selben Bash-Batch** wie Phase 1 + Phase 2 (identischer Sekunden-Timestamp → Aggregator erkennt Parallelität)
- `PHASE_END [Phase 2.5/N] ... (parallel with Phase 1+2)` nach Agent-Return

Ohne diesen Suffix zählt `ASSESSMENT_PHASES` (`agent_logger.py:1214`) Phase 2.5 als sequentielle Wall-Clock-Dauer und addiert sie in der Run-Statistics-Appendix — Ersparnis wird unsichtbar oder gar negativ.

**Hinweis:** Phase 2.5 emittiert heute **keine** PHASE_START/PHASE_END-Marker (`grep PHASE_START agents/phases/phase-group-recon.md` → kein Treffer für Phase 2.5). Bei sequentieller Ausführung fällt das nicht auf (Fallback auf parametrische Estimates). Bei Parallelisierung **erstmalig nötig**.

**5c. `stage-stats.jsonl`-Cost-Eintrag für config-scanner manuell schreiben (R3).**

`phase-group-threats.md:371` dokumentiert das Hook-Logger-Problem:
> *"Background agents spawned via `run_in_background: true` do not reliably emit `AGENT_INVOKE` log lines through the hook logger — production runs showed only 1 of 5 dispatched STRIDE analyzers logged"*

Heute: config-scanner = `run_in_background:false` → PostToolUse-Hook feuert zuverlässig → `stage-stats.jsonl` enthält Cost-Eintrag.
Nach Hebel #1: `true` → Hook potenziell verpasst → **`verify_run_costs.py` undercount für config-scanner**.

Zwei Optionen:
1. **(empfohlen)** Orchestrator schreibt nach `AGENT_DONE` selbst eine `stage-stats.jsonl`-Zeile (analog dem STRIDE-Workaround aus `phase-group-threats.md:371-380`).
2. Bewusst akzeptieren — dann in Hebel-#1-Plan dokumentieren ("config-scanner cost undercounted by ~$0.001/run bei 15 Haiku-Turns; akzeptabel weil <1% Pipeline-Cost"). Empfehlung: Option 1, kostet wenig Aufwand und hält die Cost-Aggregation konsistent.

### Mögliche Nebenwirkungen

| ID | Risiko | Wahrscheinlichkeit | Mitigation |
|---|---|---|---|
| | **Schema-Validator schlägt fehl, Phase 9 verbraucht leere `CONFIG_SCAN_FINDINGS`** | gering | bereits durch Stub + Failure-Handling abgedeckt (`phase-group-recon.md:269-273`). Verhalten unverändert. |
| | **`HAS_IAC_SURFACE`-Check läuft jetzt VOR Phase 2 statt nach** | keine Funktionsänderung | Filesystem-Check ist deterministisch, idempotent, nicht von Recon abhängig. |
| | **Tests in `tests/test_agent_definitions.py` brechen** | gering | Tests pinnen Turn-Budgets und Frontmatter, nicht Phasen-Ordering. Trotzdem vor Merge: `pytest tests/test_agent_definitions.py` laufen lassen. |
| | **`AGENT_INVOKE`/`AGENT_DONE`-Ordering in `.agent-run.log` zerbricht Postmortem-Parser** | mittel | Drei parallele Invokes müssen in **einem** Bash-Batch loggen (chronologische Reihenfolge bleibt erhalten). `scripts/agent_logger.py:466` bestätigt explizit *"eliminates the lost-update race on parallel hook processes — no fcntl"* — Python `open(path, "a")` nutzt O_APPEND, POSIX-atomar für Log-Zeilen ≤ PIPE_BUF (4096 B). |
| | **Cache-Verhalten: Phase 2 fingerprint-skip + config-scan fingerprint-miss läuft jetzt anders** | gering | Config-Scanner hat heute keinen eigenen Fingerprint-Skip. Bleibt so. Skip-Pfad ist `HAS_IAC_SURFACE=false`-only. |
| | **Incremental-Mode (`INCREMENTAL=true`): Fast-Path skip-all sub-agents** | keine Änderung | Fast-Path skipt heute schon Phase 2.5 mit den anderen. Bleibt so. |
| | **Doku-Drift in `appsec-threat-analyst.md` (Phase-2.5-Beschreibung)** | hoch | Zeitgleich mit `phase-group-recon.md` redigieren. Such-Pattern: `Phase 2\.5:` in `agents/appsec-threat-analyst.md`, `agents/phases/phase-group-recon.md`, `skills/create-threat-model/SKILL-impl.md`. |
| **R1** | **`ASSESSMENT_PHASES`-Aggregator zählt Phase 2.5 als sequentielle Wall-Clock** | **hoch (sichtbar in jeder Run-Statistics-Appendix)** | PHASE_START/PHASE_END für Phase 2.5 mit Parallel-Suffix emittieren (siehe Schritt 5b). `phase-group-finalization.md:1142` ist die Aggregator-Regel; Phase 1 ist das funktionierende Vorbild. |
| **R2** | **File-Polling statt Agent-Return-Wait → verschwendete Turns oder Race** | mittel | Wait-Block aus Schritt 3 = Erweiterung des bestehenden Agent-Return-Waits, kein File-Polling. `phase-group-recon.md:14` ist die normative Wait-Logik. |
| **R3** | **`stage-stats.jsonl` undercounted config-scanner-Cost** | mittel | Manueller `stage-stats.jsonl`-Write durch Orchestrator nach `AGENT_DONE` (Schritt 5c). Evidenz: `phase-group-threats.md:371` — bekanntes Hook-Reliability-Problem bei `run_in_background:true`. |
| **R4** | **State-Matrix unvollständig (3 boolesche Flags, 8 Kombinationen)** | mittel | Vollständige Enumeration in Schritt 2 als Tabelle. Edge-Cases: `CTX_SKIP+RECON_SKIP+HAS_IAC=true` → config allein → `run_in_background:false`. |
| **R5** | **`compgen -G "**/$pattern"` Cold-Cache-Performance auf Monorepos** | gering | Smoke-Test misst `HAS_IAC_SURFACE`-Check-Dauer (akzeptabel < 500 ms). Auf sehr großen Repos ggf. nur Top-Level-Globs ohne `**/` rekursiv. |
| **R6** | **`CONFIG_SCANNER_MODEL` nicht in Pre-Phase resolved** | mittel | Schritt 1b: Resolution in dieselbe Pre-Phase-Bash-Batch wie `RECON_SCANNER_MODEL`/`CONTEXT_RESOLVER_MODEL` ziehen. Verifizieren via grep. |
| **R7** | **Background-Agent-Concurrency-Limit ungedockumentiert** | gering | Smoke-Test: 3 concurrent Agent dispatches + 1 nohup PID auf Juice-Shop. Anthropic-API-Limit nicht in Codebase pinned; sehr wahrscheinlich kein Limit < 5. |
| **R8** | **Modell-Drift AGENTS.md ↔ phase-group-recon.md** | hoch | Vorbedingung P1: vor jedem Edit klären. Sonst zementiert Schritt 4 die falsche Variante. |
| **R9** | **dep-scan ungewollt in Parallel-Batch gezogen** | gering | Schritt 2 sagt explizit *"dep-scan-Launch-Pfad unverändert — bleibt post-Recon-Return wegen Manifest-Abhängigkeit"*. dep-scan braucht `$MANIFESTS` aus `.recon-summary.md`. |

### Erwartete Ersparnis

- Wenn `HAS_IAC_SURFACE=true` (typisch für Apps mit Dockerfile/GH-Actions): **~15 Turns Wall-Clock**, da config-scanner heute nach Phase 2 sequentiell läuft. In Sekunden: empirisch ~30–90 s (15 Haiku-Turns mit kleinem Working-Set).
- Wenn `HAS_IAC_SURFACE=false`: keine Änderung (Pre-Check + Stub wie heute).
- Auf Juice-Shop (8-Run-Telemetrie aus M3.4): ja, IaC-Oberfläche vorhanden → Hebel greift.

### Verifikations-Protokoll

1. **Smoke-Test auf Juice-Shop:**
   ```bash
   /create-threat-model --assessment-depth standard
   ```
   - `.config-scan-findings.json` muss existieren und valide gegen `schemas/config-scan-findings.schema.yaml` sein
   - `.agent-run.log`: `AGENT_INVOKE` für config-scanner liegt **gleichzeitig** mit recon-scanner (gleicher Sekunde)
   - `.agent-run.log`: `AGENT_DONE` für config-scanner liegt **vor** `[Phase 2.6/N] STEP_START Route inventory pre-pass`
   - **R1-Check:** `PHASE_START [Phase 2.5/N]` Timestamp == `PHASE_START [Phase 1/11]` Timestamp (Sekunden-Genauigkeit). `PHASE_END [Phase 2.5/N]` enthält Substring `"(parallel with Phase 1+2)"`.
   - **R3-Check:** `cat $OUTPUT_DIR/.stage-stats.jsonl | jq 'select(.agent == "appsec-config-scanner")'` liefert genau eine Zeile mit nicht-null `cost_usd` und `tokens_total`.
   - **R5-Check:** Im `.agent-run.log` Δ zwischen `Pre-Phase start` und `HAS_IAC_SURFACE resolved` < 500 ms.
   - **R7-Check:** 3 separate `AGENT_INVOKE`-Zeilen innerhalb derselben Sekunde, keine `Anthropic API error`-Zeile im Log.

2. **Time-Diff-Check (Wall-Clock-Ersparnis):**
   - Vorher: Zeitstempel(`AGENT_INVOKE recon-scanner`) → Zeitstempel(`AGENT_DONE config-scanner`) ≈ Recon-Dauer + Config-Dauer
   - Nachher: ≈ max(Recon-Dauer, Config-Dauer)
   - **R1-Cross-Check:** In `threat-model.md` Run-Statistics-Appendix muss Phase-2.5-Zeile mit Parallel-Marker erscheinen (analog Phase 1), und die Total-Wall-Clock darf NICHT um Phase-2.5-Dauer steigen.

3. **Regressionstest:** Threat-Count + Threat-IDs auf Juice-Shop müssen identisch zum Baseline-Run sein. Config-Scanner-Output (`source: "config-scan"`-Threats) muss byte-identisch sein (Determinismus aus `agents/appsec-config-scanner.md:102`: *"Deterministic — identical input produces identical output"*).

4. **Failure-Pfad-Test:** Auf einem Repo ohne IaC-Surface — `HAS_IAC_SURFACE=false` muss greifen, Stub-File geschrieben werden, kein Agent dispatched, kein `AGENT_INVOKE` in der Log.

5. **State-Matrix-Test (R4):** Mindestens drei Kombinationen explizit testen:
   - `--incremental` mit RECON_SKIP=true + HAS_IAC=true → nur context + config dispatched
   - `--full` mit HAS_IAC=true → 3 Agents parallel
   - Cache-Hit auf context AND fingerprint-skip auf recon → nur config-scanner allein mit `run_in_background:false`

### Touch-Liste (Dateien)

- `agents/phases/phase-group-recon.md` (Zeilen 176–273): Phase 2.5 Abschnitt
- `agents/appsec-threat-analyst.md`: "Phases 1–2: Reconnaissance & Context (parallel dispatch)" + "Phase 2.5" Block + Pre-Phase Bash-Batch (für `CONFIG_SCANNER_MODEL`-Resolution + `HAS_IAC_SURFACE`-Check + `PHASE_START` Phase 2.5)
- `skills/create-threat-model/SKILL-impl.md`: Phase-Übersicht (Zeile 45 "Out:"), CONFIG_SCANNER_MODEL-Env-Block Zeile 2305
- **`AGENTS.md`**: Tabelle Zeile 232–235 (Phase 2.5 conditional), Zeile 184 Hinweis. **Modell-Pin Zeile 215 (P1) muss VOR Hebel #1 mit `phase-group-recon.md` synchronisiert werden.**
- Keine Schema-Änderungen
- Keine Skript-Änderungen für die Parallelisierung an sich. **Aber:** R3-Mitigation (Option 1) verlangt einen manuellen `stage-stats.jsonl`-Write im Orchestrator-Bash. Falls dafür ein Helfer in `scripts/` bereits existiert (analog STRIDE-Workaround), nutzen — sonst inline-Bash mit `jq`/`printf`.

---

## Vertagt — STRIDE Tail-Pod-Optimierung (war Hebel #2)

Aus dem Umsetzungsplan herausgenommen am 2026-05-24. Grund: Premisse korrekt (`max(Pod-Dauer)` dominiert Phase 9 Wall-Clock, file-services empirisch bei 179 s vs auth-identity 73 s laut `phase-group-threats.md:339-340`), aber Plan war nicht umsetzungsreif:

1. **M21-Prior-Art nicht referenziert.** `phase-group-recon.md` Step 0b betreibt bereits `extract_data_relations.py` als deterministisches FOCUS_PATHS-Discovery-Skript für `data-layer` (170 s mean → Optimierungsziel). Vor einem neuen Postmortem-Skript (`analyze_stride_tail.py`) müsste das M21-Muster als Template übernommen werden.
2. **Ersparnis 70-100 s ist spekulativ.** Die "30-40 % schneller"-Annahme hat keine Stütze außer der hypothetischen Übertragung der frontend/file-handling-Erfahrung.
3. **Neue Komponenten-Familien (`data-persistence-large`, `admin-panel`, `messaging-queue`) erfunden** statt aus `scripts/classify_component.py` abgeleitet.
4. **Tooling-Duplikation ungeprüft.** Ob `scripts/agent_logger.py` oder vergleichbare Postmortem-Tools schon per-Pod-Latenzen aggregieren, wurde nicht verifiziert.

**Wieder aufnehmen, wenn:** Hebel #1 gemessen und gelandet ist UND ein deterministisches Discovery-Skript analog `extract_data_relations.py` für den Top-Tail-Pod (vermutlich `file-services`) gebaut werden kann. Splitting-Pfad (Komponenten physisch teilen) bleibt abgelehnt — bricht COMPONENT_PATHS-Contract (`appsec-stride-analyzer.md:196-202`), M19 Auth-Invariant (`classify_component.py:~173`), Compound-Chains (`schemas/threats-merged.schema.yaml:154`) und Incremental-Mode-Mapping.

---

## Reihenfolge der Umsetzung

Nur Hebel #1. Nach Umsetzung: PROGRESS.md aktualisieren mit empirischen Vorher/Nachher-Zahlen aus 3-Run-Mitteln.

---

## Explizit nicht umgesetzt (Audit-Entscheidungen)

| Vorschlag | Status | Grund |
|---|---|---|
| threat-analyst auf Haiku | abgelehnt | Orchestrator-Pin in AGENTS.md; Cross-Component-Synthese bricht; kleines Token-Volumen → kein ROI |
| STRIDE-Analyzer pauschal auf Haiku | abgelehnt | Reasoning-Kern der Pipeline; Qualitätsverlust nicht messbar trivial recoverable |
| Per-Letter-Parallelität (S/T/R/I/D/E je eigener Pod) | abgelehnt | Spawn-Overhead × Merge-Komplexität > Gewinn |
| Phase 10/10a/10b parallelisieren | abgelehnt | Echte Datenabhängigkeit: triage-validator konsumiert `evidence_check` aus evidence-verifier |
| Architect-Reviewer Checks 1–13 vor Renderer | abgelehnt | Reviewer liest `threat-model.md` (gerenderte Narrative); Repair-Plan zielt auf Fragmente nach Phase 11; Kohärenz-Check Narrative ↔ YAML braucht beide |
| QA-Reviewer ↔ Architect-Reviewer parallel | offen | Beide post-render, beide eigene Outputs — Skill-Order-Abhängigkeit ungeprüft. Wenn Hebel #1 nicht reicht, hier vertiefen |
| STRIDE Tail-Pod FOCUS_PATHS-Tuning | vertagt | Premisse OK, Plan unreif — siehe "Vertagt"-Sektion oben |
| Komponenten physisch splitten | abgelehnt | Bricht COMPONENT_PATHS-Contract, M19-Invariant, Compound-Chains, Incremental-Mapping |

---

## Referenzen (verbatim citations)

- `agents/appsec-config-scanner.md:3` — config-scanner description ("invoked … during Phase 2.5 (after recon, before STRIDE fan-out)")
- `agents/appsec-config-scanner.md:26-31` — Inputs (no recon-summary)
- `agents/appsec-config-scanner.md:35-71` — Process (reads config-iac-checks.yaml + filesystem globs)
- `agents/appsec-config-scanner.md:102` — Determinismus-Aussage
- `agents/phases/phase-group-recon.md:176-273` — Phase 2.5 vollständig (zu editieren)
- `agents/phases/phase-group-recon.md:227-228` — falsche Sequentialitäts-Begründung (zu korrigieren)
- `agents/appsec-architect-reviewer.md:3` — Architect-Reviewer description (liest threat-model.md/.yaml/Management Summary; rechtfertigt Reject "Architect-Reviewer Checks 1–13 vor Renderer")
- `AGENTS.md:184` — "Phase 2.5 conditional on IaC surface" (Bestätigung für `HAS_IAC_SURFACE`-Gate)
- `AGENTS.md:215` — config-scanner Modell-Pin "Haiku Always" (steht im Konflikt zu `phase-group-recon.md` Dispatch-Block, der `claude-sonnet-4-6` als Default nennt — vor Hebel #1 zu klären)

**Vertagt-Sektion (STRIDE Tail-Pod) referenziert zusätzlich:**
- `agents/phases/phase-group-threats.md:339-340` — file-services/auth-identity Tail-Telemetrie (M3.4)
- `agents/appsec-stride-analyzer.md:144` — FOCUS_PATHS read-first-Semantik
- `agents/appsec-stride-analyzer.md:196-202` — COMPONENT_PATHS Threat-Attribution-Contract
- `agents/phases/phase-group-recon.md` Step 0b — `extract_data_relations.py` als M21-Template
- `scripts/classify_component.py` (Block bei `if canonical == "auth-identity"`) — M19 Auth-Invariant
- `schemas/threats-merged.schema.yaml:154` — Compound-Chain Mention (einziger Treffer im Schema)
