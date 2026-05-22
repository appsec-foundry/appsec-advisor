# Kontinuierlicher AppSec-Fortschritt in Claude Code

## Ziel

Der Threat-Model-Run soll in der Claude-Code-Konsole kontinuierlich sichtbar
bleiben: aktueller Pipeline-Schritt, grober Gesamtfortschritt, realistische
Restzeit und ein klarer Hinweis, wenn eine Phase laenger als erwartet keine
neuen Signale liefert. Die Anzeige darf nicht erst bei Phasengrenzen springen.

Nicht-Ziel: ein exakt mathematischer Prozentwert. Der Run enthaelt LLM-Arbeit,
parallel laufende Subagents und repo-abhaengige IO-Zeit. Die UI soll daher
einen ehrlichen Schaetzwert mit Status/Confidence anzeigen, nicht scheinbare
Praezision.

## Verifikation der Claude-Code-Konsole

Die belastbare Oberflaeche fuer kontinuierliche Anzeige ist `statusLine`.

- Claude Code beschreibt `statusLine` als dauerhaft sichtbare Statusleiste
  unten in der UI. Das Script bekommt Session-JSON auf stdin und alles, was es
  auf stdout schreibt, wird angezeigt.
  Quelle: https://code.claude.com/docs/en/statusline
- `refreshInterval` fuehrt das Statusline-Command alle N Sekunden erneut aus;
  Minimum ist 1 Sekunde. Die Doku nennt genau den Fall, dass event-getriebene
  Updates waehrend idle/background-subagent-Phasen sonst still werden koennen.
  Quelle: https://code.claude.com/docs/en/statusline
- `statusLine` laeuft lokal und verbraucht keine API-Tokens. Sie kann
  waehrend Autocomplete, Help-Menues und Permission-Prompts kurz ausblenden,
  kehrt danach aber zurueck.
  Quelle: https://code.claude.com/docs/en/statusline
- `subagentStatusLine` kann zusaetzlich die sichtbaren Subagent-Zeilen im
  Agent-Panel anpassen. Plugins duerfen eine Default-`subagentStatusLine`
  ausliefern.
  Quelle: https://code.claude.com/docs/en/statusline
- Plugin-Default-Settings unterstuetzen laut aktueller Plugin-Doku nur
  `agent` und `subagentStatusLine`, nicht allgemein `statusLine`. Ein globaler
  AppSec-Fortschrittsbalken muss also ueber User-/Project-Settings oder einen
  Setup-Hinweis konfiguriert werden; als Plugin-Default geht nur die
  Subagent-Zeile.
  Quelle: https://code.claude.com/docs/en/plugins

Nicht geeignete Primaerwege:

- Hook-`stderr` ist fuer interaktive Claude-Code-UI nicht verlaesslich genug.
  Das Repo dokumentiert diese Grenze bereits in
  `skills/create-threat-model/SKILL-impl.md`.
- Hook-`terminalSequence` kann keine freie Inline-Konsole zeichnen. Die Doku
  erlaubt nur begrenzte OSC-Sequenzen/BEL fuer Titel/Notifications/Taskbar-
  Progress; CSI-Cursor- und Farbsequenzen werden verworfen.
  Quelle: https://code.claude.com/docs/en/hooks
- Plugin-Monitors liefern stdout-Zeilen als Notifications an Claude. Das ist
  gut fuer Reaktionen/Diagnostik, aber nicht als ruhige, dauerhafte
  User-Fortschrittsanzeige.
  Quelle: https://code.claude.com/docs/en/plugins

## Bestehende Signale im Repo

Bereits vorhanden und wiederverwendbar:

- `.appsec-progress.json` aus `scripts/log_event.py`: letzter strukturierter
  Phase-/Step-/Agent-Status. (Verifiziert: `log_event.py` schreibt
  `phase-start/phase-end/step-start/step-end` in diese Datei.)
- `.appsec-checkpoint`: aktuelle Phase und Status.
- `.progress/<component>.json`: STRIDE-Komponentenschritt 1/9 bis 9/9.
- `.stride-*.json`: fertige STRIDE-Komponenten.
- `.appsec-lock`: Heartbeat/Liveness.
- `.active-tool-calls/*.json`: aktuell laufende Tool-Aufrufe, soweit Hooks sie
  sehen.
- `.skill-config.json`: Depth, Mode, QA/Architect-Konfiguration.
- `scripts/estimate_duration.py`: bestehende Dauer-Schaetzung mit
  last-run-cache, component durations, incremental dirty set und parametric
  fallback.
- `data/phase-budgets.yaml` und `scripts/phase_budgets.py`: Stall-/Silence-
  Schwellwerte.

Bereits vorhandene Status-/Watcher-Scripts (NICHT duplizieren, sondern
weiterverwenden):

- `scripts/appsec_status.py` (679 Zeilen) mit `--json --live`-Flags:
  liefert bereits Plugin-Version, Capsules, Last-Run-Identity, Config-State,
  Fast-Path-Preview. Aufgerufen vom `/appsec-advisor:status`-Skill. **Die
  neue Snapshot-Schicht muss dieses Script erweitern, nicht ersetzen.**
- `scripts/watch_run.py`: phase-aware Stall-Detection. Liest
  `.appsec-checkpoint`, nutzt `phase_budgets.threshold_for_phase()`,
  multipliziert mit `--stall-multiplier` (Default 1.5). **Statusline ruft
  die Stall-Logik dieses Scripts auf, baut sie nicht nach.**
- `scripts/stride_progress.py`: zaehlt `.stride-*.json` gegen
  `.progress/*.json`, gibt `K/N ready` plus langsamsten Component-Step aus,
  Heartbeat-Dedup via `.progress/.last-print`. **Statusline delegiert
  Phase-9-Detail an dieses Script.**

Wichtige Luecke (verifiziert):

- `.appsec-progress.json` wird heute nicht konsequent fuer alle Stage-1
  Phasen aktualisiert. `grep -c log_event.py agents/phases/*.md` = 0:
  **kein einziger Phase-Group-Agent ruft `log_event.py` auf.** Stattdessen
  schreiben sie raw `echo "... PHASE_START ..." >> .agent-run.log` (Belege:
  `phase-group-architecture.md:1003,1008,1013` fuer Phasen 5/6/7;
  `phase-group-finalization.md:86,228,259,275,613,1431` fuer Phase 11).
  Folge: `.appsec-progress.json` reflektiert ueberhaupt nur dort den Stand,
  wo der Orchestrator (nicht die Phase-Group-Agents) `log_event.py` ruft.
  Fuer eine ruhige Statusline muessen Phase- und Substep-Signale in den
  Phase-Group-Agents auf `log_event.py` umgestellt werden.

## Vorgeschlagene Architektur

### 0. Verification-Spike (MUSS zuerst, vor allem anderen)

Die gesamte Architektur steht und faellt mit einer ungeprueften Annahme:
**statusLine refresht weiter, waehrend der Hauptagent im `Agent`-Tool auf
einen Subagent wartet.** SKILL-impl:1528 dokumentiert genau das gegenteilige
Verhalten: *"The Agent tool dispatches Stage 1 in foreground and blocks
the chat for the full duration."* Ob `refreshInterval` waehrend dieses
Blockings tickt, ist nicht aus der Doku ableitbar und nicht im Repo getestet.

Spike-Setup (≤ 1 Stunde):

1. Trivialer Statusline-Renderer: `python3 -c "import json,sys,time; \
   sys.stdin.read(); print(f'tick {int(time.time())}')"`.
2. `.claude/settings.json` mit `refreshInterval: 2` darauf zeigen.
3. Trivialer Skill, der einen Subagent dispatcht, der `sleep 120` macht.
4. Beobachten: aendert sich der `tick`-Wert in der Statusbar waehrend
   der 120 s? Wenn nein → die ganze Architektur ist tot, und es muss
   stattdessen ein PreToolUse/PostToolUse-Hook auf `terminalSequence`
   mit OSC-9;4 fuer Taskbar-Progress evaluiert werden.
5. Ergebnis als `.run-observations-statusline-spike.md` ablegen.

Erst wenn der Spike `PASS` liefert, geht es mit den weiteren Abschnitten
weiter. Andernfalls Plan abbrechen und Alternativweg neu skizzieren.

### 1. Snapshot-Schicht — `appsec_status.py` erweitern

**Keine neue Datei.** `scripts/appsec_status.py` existiert bereits mit
`--json --live`-Flags. Erweitern statt duplizieren, damit es nur eine
Status-Wahrheit gibt.

Erweiterungen in `appsec_status.py --live --json`:

- liest `OUTPUT_DIR` read-only (das macht es schon)
- kombiniert zusaetzlich: Checkpoint, progress files, lock, skill config,
  duration estimate, optional active tool calls
- ergaenzt im JSON-Output die Felder:
  - `running: true|false`
  - `phase`, `stage`, `label`, `agent`
  - `percent_estimate` als 0..100
  - `eta_seconds`, `eta_label`
  - `confidence: measured|component|parametric|unknown`
  - `silence_seconds`, `stale: true|false` (delegiert an
    `watch_run.compute_stall()` oder aequivalenten extrahierten Helper)
  - `stride_ready`, `stride_expected`, `stride_components[]` (delegiert
    an `stride_progress.snapshot()` oder aequivalenten extrahierten Helper)
  - `display_line` fuer direkte CLI-/statusLine-Nutzung

Kein Report-Artefakt wird veraendert. Erweiterung ist rein observability.
Backwards-Kompat: ohne `--live` aendert sich nichts am bestehenden Output.

Refactor-Vorbedingung: `watch_run.py` und `stride_progress.py` muessen ihre
Kern-Snapshot-Funktionen als importierbare Helper exponieren (heute beides
CLI-only). Das ist die einzige strukturelle Aenderung an Bestandsscripts.

### 2. Statusline-Renderer

Neue Datei: `scripts/appsec_statusline.py`.

Aufgabe:

- liest Claude-Code-statusLine-stdin-JSON
- findet den passenden Run:
  1. `APPSEC_STATUS_OUTPUT_DIR`, falls gesetzt
  2. Pointer-Datei in `/tmp/.appsec-current-run-<uid>-<repohash>.json`
  3. Default `<workspace.project_dir>/docs/security`
- ruft `appsec_status.py --live --json` als Subprocess (oder importiert
  die Snapshot-Funktion direkt, wenn `PYTHONPATH` das hergibt)
- rendert eine kurze, terminaltaugliche Zeile, z.B.:

```text
AppSec [######----] 61% · ETA ~14m · Phase 9/11 STRIDE · 3/5 ready · auth 4/9
```

Bei Stillstand:

```text
AppSec [######----] 61% · ETA ~14m · Phase 9/11 STRIDE · no update 6m (watch)
```

Formatregeln:

- Standardausgabe muss kurz bleiben, da Statusbars begrenzte Breite haben.
- **Default ist ASCII** (`[######----]`). statusLine sieht kein TTY, daher
  ist Encoding-Detection unzuverlaessig — Mojibake-Risiko in der Statusbar.
  Unicode-Balken nur opt-in via `APPSEC_STATUSLINE_UNICODE=1`.
- Keine langen Tabellen, keine mehrzeilige Default-Ausgabe.

Performance-Vertrag (hard, sonst Statusbar laggt bei 2 s-Refresh):

- **Hard target: < 50 ms wall-clock** pro Aufruf (Python3-Cold-Start
  allein liegt bei ~80 ms — daher kein eigener Python-Prozess, sondern
  entweder Long-running-Daemon mit Unix-Socket oder Shell-Wrapper, der
  `appsec_status.py` nur cached/throttled aufruft).
- Erlaubt: nur kleine JSON-Reads aus `$OUTPUT_DIR`.
- Verboten: `git`-Aufrufe, Netzwerk, `find`, rekursive `glob`.
- Harter Watchdog: Subprocess-Timeout 200 ms, bei Ueberschreitung
  letzten gecachten Wert aus `/tmp/.appsec-statusline-cache-*` zeigen.
- Throttle: wenn `appsec_status.py --live --json` teurer als 50 ms ist,
  cached Ergebnis fuer N Sekunden in `/tmp/.appsec-statusline-cache-<uid>.json`
  (TTL = `refreshInterval`, default 2 s); statusline-Aufrufe innerhalb der
  TTL lesen nur den Cache.

### 3. Run-Pointer fuer `--output`

Die Skill-Preambel sollte beim Run-Start eine Pointer-Datei schreiben:

```text
/tmp/.appsec-current-run-<uid>-<repohash>.json
```

Inhalt:

```json
{
  "repo_root": "/abs/repo",
  "output_dir": "/abs/output",
  "started_at": 1760000000,
  "expires_at": 1760007200,
  "mode": "full",
  "depth": "standard"
}
```

Warum `/tmp`: Die statusLine bekommt von Claude Code zwar cwd/workspace im
stdin, aber nicht zuverlaessig die Skill-env-vars. Ein `/tmp`-Pointer ist
sessionuebergreifend lokal, billig und funktioniert auch, wenn `--output`
ausserhalb von `docs/security` liegt.

Cleanup (robust gegen Skill-Crash, da `runtime_cleanup.py` `/tmp`-Pointer
nicht kennt):

- Pointer am Ende sauber entfernen oder auf `completed_at` setzen.
- **`expires_at`** ist Pflichtfeld: `started_at + 2 × estimated_total_seconds`
  als harte Obergrenze. statusLine ignoriert jeden Pointer mit
  `now > expires_at` und behandelt den Run als `idle`.
- Zusaetzlich Lock-Liveness-Check: statusLine ignoriert den Pointer auch,
  wenn `<output_dir>/.appsec-lock` aelter als
  `phase_budgets.default_heartbeat_stale_seconds()` ist oder fehlt.
- Wenn die Datei alt ist oder `output_dir` keine Lock-/Progress-Dateien mehr
  hat, zeigt die Statusline nur `AppSec idle`.

### 4. Dauer- und Prozentmodell

Die Statusline soll nicht nur Phasen zaehlen. Sie soll einen gewichteten,
zeitbasierten Fortschritt anzeigen.

Input:

- Persistiertes Ergebnis von `estimate_duration.py` als
  `$OUTPUT_DIR/.appsec-estimate.json`.
- Aktuelle Phase aus `.appsec-checkpoint`.
- Letzte strukturierte Aktualisierung aus `.appsec-progress.json`.
- Phase-Start-Epoch aus `.phase-epoch`, wenn vorhanden.
- STRIDE-Komponentenfortschritt aus `.progress/*.json`.
- Fertige `.stride-*.json`.
- Baseline-Komponentendauern aus `.appsec-cache/baseline.json`, wenn vorhanden.

Modell:

- Stage-Gewichte kommen aus `.appsec-estimate.json`.
- Innerhalb Stage 1 werden Phasengewichte aus `estimate_duration.py`
  abgeleitet, nicht aus `data/phase-budgets.yaml`. Die Budgets sind
  Stall-Schwellen, keine ETA.
- Innerhalb der aktuellen Phase wird der Fortschritt kontinuierlich
  interpoliert:
  - `phase_fraction = min(0.92, elapsed / expected_phase_seconds)`
  - fuer Phase 9 ersetzt/ergaenzt STRIDE-Komponentenfortschritt die reine
    Zeitinterpolation
  - Phase-Ende setzt die Phase auf 100 Prozent
- Fortschritt darf innerhalb eines Runs nicht sichtbar rueckwaerts springen.
  Falls ein neuer Snapshot niedriger waere, clamp auf den letzten sichtbaren
  Wert aus einer kleinen `/tmp`-Cache-Datei.
- ETA wird als Bereich gerendert, wenn die Quelle unsicher ist:
  - measured/component: `ETA ~14m`
  - parametric: `ETA ~12-18m`
  - unknown/no estimate: `ETA ?`

Stillstand:

- `silence_seconds` = Alter der letzten `.appsec-progress.json` oder des
  aktuellsten relevanten Progress-/Tool-Call-Files.
- `stale=true`, wenn `silence_seconds` den phasenbewussten Threshold aus
  `phase_budgets.threshold_for_phase()` ueberschreitet.
- Anzeige bleibt ruhig, aber sichtbar: `no update 6m`, nicht Spam.

### 5. Bessere strukturierte Fortschrittssignale

Damit die Statusline nicht nur raten muss. **Konkrete Audit-Tabelle der
betroffenen Stellen (verifiziert per `grep -c log_event.py`):**

| Datei | Heutige Form | Umstellen auf |
|---|---|---|
| `agents/phases/phase-group-architecture.md:1003,1008,1013` | raw `echo "... PHASE_START [Phase 5/6/7]" >> .agent-run.log` | `log_event.py phase-start` |
| `agents/phases/phase-group-architecture.md:16,56,77` | raw `echo` fuer Phase-Group-Start/Repair/Burst | `log_event.py phase-start` / `info` |
| `agents/phases/phase-group-finalization.md:86` | raw `echo "... PHASE_START [Phase 11/11]"` | `log_event.py phase-start` |
| `agents/phases/phase-group-finalization.md:228,259,275,613,1431` | raw `echo "... STEP_START [Phase 11] [k/N] ..."` | `log_event.py step-start` |
| `agents/phases/phase-group-recon.md`, `phase-group-threats.md` | TBD im Audit ergaenzen | `log_event.py phase-start/end` |
| `agents/appsec-threat-analyst.md` | Phase-Switching-Echoes im Orchestrator | `log_event.py` |

Weitere Aenderungen:

- `scripts/log_event.py` sollte optional numerische Felder schreiben:
  `updated_epoch`, `phase_started_epoch`, `stage`, `stage_total`.
- `skills/create-threat-model/SKILL-impl.md` soll das `EST_JSON` aus
  `estimate_duration.py` nach `$OUTPUT_DIR/.appsec-estimate.json` schreiben.
- Stage 2/3/4 Start/End sollten ebenfalls `.appsec-progress.json`
  aktualisieren, nicht nur TaskList/Log.
- Phase 9 ist bereits am besten instrumentiert (via `stride_progress.py`);
  hier nur `expected_count` und ggf. Component-Komplexitaet in eine
  strukturierte Datei aufnehmen.

Migration-Reihenfolge: zuerst `phase-group-finalization.md` (Phase 11 ist
die laengste Phase und liefert die meisten Step-Updates → groesster UX-
Hebel), dann `phase-group-architecture.md`, dann der Rest.

Keine per-phase `TaskCreate`-Erweiterung. Das widerspricht dem bestehenden
TaskList-Vertrag in `SKILL-impl.md` und wuerde die UI eher unruhiger machen.

### 6. Claude-Code-Konfiguration

Fuer lokale Projektentwicklung kann `.claude/settings.json` spaeter erweitert
werden:

```json
{
  "statusLine": {
    "type": "command",
    "command": "python3 /home/mrohr/appsec-advisor/scripts/appsec_statusline.py",
    "refreshInterval": 2,
    "padding": 1
  }
}
```

Fuer Plugin-Auslieferung:

- Script mitliefern.
- In `HELP.txt`/README dokumentieren, wie Nutzer `statusLine` aktivieren.
- Optional `settings.json` im Plugin-Root mit `subagentStatusLine`, weil das
  laut Plugin-Doku als Default erlaubt ist.
- Nicht davon ausgehen, dass der Plugin eine globale `statusLine` automatisch
  setzen kann.

## Implementierungsschritte

0. **Verification-Spike (BLOCKER fuer alles andere).**
   - Triviale Statusline + Subagent mit `sleep 120`.
   - Beweisen: `refreshInterval` tickt waehrend `Agent`-Tool-Blocking.
   - Ergebnis als `.run-observations-statusline-spike.md`.
   - Bei FAIL: Plan abbrechen, Alternativweg neu skizzieren (z.B.
     OSC-9;4-Taskbar-Progress via `terminalSequence`-Hook).

1. **Helper aus `watch_run.py` und `stride_progress.py` extrahieren.**
   - `watch_run.compute_stall(output_dir, depth) -> StallSnapshot`.
   - `stride_progress.snapshot(output_dir, expected) -> StrideSnapshot`.
   - CLI-Verhalten unveraendert lassen (heutige Aufrufer brechen sonst).

2. **`scripts/appsec_status.py --live --json` erweitern.**
   - Nutzt die neuen Helper aus Schritt 1.
   - Fuegt die in Section 1 gelisteten Felder hinzu
     (`percent_estimate`, `eta_*`, `confidence`, `silence_seconds`,
     `stale`, `stride_*`, `display_line`).
   - Tests mit Fake-Output-Dirs: idle, Phase 1, Phase 9 mit Komponenten,
     stale, completed.

3. **`scripts/appsec_statusline.py` bauen.**
   - stdin-JSON robust parsen.
   - Output-dir discovery inkl. `/tmp`-Pointer (mit `expires_at` +
     Lock-Liveness-Check).
   - Default ASCII, Unicode opt-in via `APPSEC_STATUSLINE_UNICODE=1`.
   - Subprocess-Call zu `appsec_status.py --live --json` mit
     Throttle-Cache in `/tmp/.appsec-statusline-cache-<uid>.json`.
   - Hard target < 50 ms; Watchdog-Timeout 200 ms → letzten Cache zeigen.
   - Tests fuer Breite, idle fallback, stale marker, Throttle, Timeout-
     Fallback.

4. **Skill-Preambel ergaenzen.**
   - `.appsec-estimate.json` schreiben (EST_JSON aus
     `estimate_duration.py`).
   - `/tmp`-current-run-Pointer schreiben **inklusive `expires_at`
     (started_at + 2× estimated_total_seconds)**.
   - Completion/error cleanup fuer Pointer ergaenzen.
   - `data/required-permissions.yaml` pruefen, weil neue Write-Ziele und ggf.
     neue Bash-Aufrufe dazukommen.

5. **Phase-Progress zentralisieren — Migration auf `log_event.py`.**
   - Audit-Tabelle aus Section 5 abarbeiten.
   - Reihenfolge: `phase-group-finalization.md` zuerst, dann
     `phase-group-architecture.md`, dann Rest.
   - Keine Report-Renderer-/Schema-Contracts veraendern.

6. **Statusline lokal aktivieren und manuell pruefen.**
   - `claude --debug` nutzen, falls die Statusline nicht erscheint.
   - Testlauf mit kuenstlichen Progress-Dateien.
   - Danach echter kurzer `--dry-run`/Quick-Run, falls verfuegbar.

7. **Optional: `subagentStatusLine`.**
   - STRIDE-Subagent-Zeilen mit Component-Step/Idle-Zeit anreichern.
   - Plugin-Root-`settings.json` nur fuer `subagentStatusLine` verwenden.

## Risiken und Gegenmassnahmen

- Risiko: Prozentwert wirkt zu exakt.
  Gegenmassnahme: `estimate`, ETA-Bereich und Confidence rendern.

- Risiko: Statusline sucht falsches Output-Verzeichnis.
  Gegenmassnahme: `/tmp`-Pointer plus Default-Fallback plus stale-expiry.

- Risiko: Statusline-Script ist zu langsam und wird alle 1-2 Sekunden
  ausgefuehrt.
  Gegenmassnahme: nur kleine JSON-Dateien lesen, keine `git`-Aufrufe, keine
  Netzwerkzugriffe, harte Timeout-/Fallback-Logik.

- Risiko: Fortschritt springt rueckwaerts, wenn Schaetzung nachzieht.
  Gegenmassnahme: sichtbaren Prozentwert pro Run in `/tmp` cachen und clampen.

- Risiko: vorhandene Runtime-Cleanup- und Audit-Vertraege werden gestoert.
  Gegenmassnahme: neue Dateien als transient dokumentieren/tests ergaenzen;
  Audit-Artefakte nicht loeschen.

## Akzeptanzkriterien

- In einer interaktiven Claude-Code-Session aktualisiert sich die AppSec-Zeile
  alle 2 Sekunden, auch wenn der Hauptagent gerade auf Subagents wartet.
- Die Anzeige zeigt Phase/Stage, Prozent-Schaetzung, ETA und Stale-Hinweis.
- Bei Phase 9 werden `K/N ready` und mindestens der langsamste aktive
  Component-Step angezeigt.
- Bei `--output <path>` zeigt die Statusline den richtigen Run.
- Bei keinem laufenden Run zeigt sie kurz `AppSec idle` oder bleibt leer.
- Unit-Tests decken Snapshot-Berechnung, Statusline-Rendering und stale
  thresholds ab.
