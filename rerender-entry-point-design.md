# Design: `--rerender` Entry Point (Render-Recovery)

**Ziel:** Ein expliziter, deterministischer Einstieg, der **Stage 2 (Renderer/Compose) + Stage 3 (QA + Re-Render-Loop)** aus den **vorhandenen** Stage-1-Artefakten fährt — **ohne Stage 1 neu zu laufen** und **ohne** dass der Incremental-No-op-Fast-Path vorgreift.

**Zwei Nutzen:**
1. **Produktiv:** Fragment editiert, oder Renderer-/QA-/Contract-Logik geändert → Report neu rendern + neu prüfen, ohne ~25 min Stage-1-Kosten (heute gibt es dafür nur `--full`, das alles neu analysiert).
2. **Verifikation:** macht `tests/e2e/run-repair.sh` zuverlässig — korrumpiere §7.2 → `--rerender` → Renderer recomposed das (analyst-authored, vom Renderer NICHT regenerierte) §7.2-Fragment → QA flaggt → **Re-Render-Loop dispatcht den fragment-fixer (M2b) live**.

---

## 1. Warum es heute nicht geht (verifizierter Ist-Zustand)

- Es existiert bereits ein Render-Recovery-Pfad: `STAGE11_CUTOFF=true` (≥3 Fragmente in `.fragments/` **und** `threat-model.md` fehlt) → Stage-2-Recovery-Dispatch (`appsec-threat-renderer`, `RESUME_FROM_PHASE=11`, reuse `.threats-merged.json`/`.triage-flags.json`/`.fragments/`) → danach normaler Post-Stage-2-Flow inkl. Stage 3 QA + Re-Render-Loop (`SKILL-impl.md` ~2403, ~2302).
- **Aber** der Incremental-No-op-Fast-Path (`SKILL-impl.md` ~868, „**before** anything else") läuft **vor** der `STAGE11_CUTOFF`-Detektion: bei `MODE=incremental` (auto, weil `threat-model.yaml` als Baseline existiert) + unverändertem Repo → sofortiger No-op-Exit. Genau das hat `run-repair.sh` mit `--resume` getroffen (241 s, nichts passiert).
- `--full`/`--rebuild` umgehen den No-op, regenerieren aber **alle** Fragmente inkl. §7.2 → die Korrumption (und jede „render existing"-Absicht) wird zerstört.

→ Es fehlt ein **expliziter** Modus, der (a) den No-op überspringt und (b) Stage 1 überspringt.

---

## 2. Der Einstiegspunkt — `--rerender`

Neuer Modus, **mutually exclusive** mit `--full`, `--incremental`, `--rebuild`, `--resume`.

**Semantik:** „Alle Stage-1-Ausgaben auf Platte sind kanonisch und werden wiederverwendet. Rendere Stage 2 neu aus den vorhandenen Fragmenten, dann Stage 3 QA + Re-Render-Loop. Stage 1 läuft nicht. Der No-op-Gate gilt nicht (explizites Re-Render ist immer gewollt)."

### 2.1 `scripts/run-headless.sh`
- `--rerender` in die Passthrough-Argliste aufnehmen (neben `--full`/`--resume`, ~Zeile 204) + in Usage/Header (~Zeile 91) dokumentieren.

### 2.2 `scripts/resolve_config.py`
- Neues Argument `--rerender` (bool) in den Parser.
- Konfliktregeln ergänzen (zur bestehenden `CONFLICTS`-Liste, ~Zeile 185):
  `("rerender","full")`, `("rerender","incremental")`, `("rerender","rebuild")`, `("rerender","resume")` → Exit 2 mit klarer Begründung.
- Im resolved JSON: `rerender: true`, und `mode: "rerender"` (eigener Mode-Wert, damit der Skill verzweigt und **nicht** auto-incremental wählt). `incremental`/`full`/`rebuild` bleiben `false`.

### 2.3 `skills/create-threat-model/SKILL-impl.md`
- `RERENDER=$(... ['rerender'] ...)` aus dem resolved JSON lesen (neben `REBUILD` etc., ~Zeile 761).
- **Früh-Branch, BEVOR** der Incremental-Fast-Path / die Stage-1-Dispatch-Logik (also vor ~Zeile 833/868/1739):

  ```
  if RERENDER == true:
      # (a) Precondition-Gate — es muss etwas zum Re-Rendern geben.
      require: threat-model.yaml, .threats-merged.json, .triage-flags.json,
               und >= MIN_FRAGMENTS Dateien unter .fragments/
      else: print "Re-render needs an existing assessment (Stage-1 artifacts
            on disk). Run a full/standard assessment first." ; exit 2
      # (b) KEIN Incremental-Fast-Path, KEIN No-op-Gate, KEIN Stage-1-Dispatch.
      # (c) Direkt der bestehende Stage-2-Dispatch (appsec-threat-renderer,
      #     reuse .fragments/ + .threats-merged + .triage-flags + yaml).
      # (d) Danach unveränderter Post-Stage-2-Flow:
      #     pre-generation backstop + hard gate + Stage 3 QA + Re-Render-Loop.
      #     → bei Contract-Drift feuert der Re-Render-Loop den fragment-fixer.
      # (e) Completion-Summary wie gehabt.
  ```

- **Wiederverwendung, kein neuer Code für Stage 2/3:** der Branch springt in den *bestehenden* Stage-2-Renderer-Dispatch + die *bestehende* Stage-3/Re-Render-Loop-Sektion. `--rerender` ist reine **Gating-/Routing**-Logik, die Stage 1 + No-op überspringt.
- Lock/Checkpoint: Skill besitzt den Lock über die Stages wie im M2.12-Split; Checkpoint-Handling identisch zum normalen Stage-2→3-Übergang.

### 2.4 Keine Agent-Änderungen
- `appsec-threat-renderer` (Stage 2) und `appsec-fragment-fixer` (Repair) bleiben unverändert — sie lesen Fragmente/Plan von Platte und kennen den Aufruf-Modus nicht.
- `appsec-threat-analyst` wird im Rerender **nie** dispatcht.

---

## 3. Sicherheit / Nebenwirkungen

- **Keine stille Qualitätsänderung:** rerender produziert denselben Output wie ein Stage-2/3-Lauf auf denselben Fragmenten; es überspringt nur die (unveränderte) Stage-1-Analyse. Wer Stage-1-Inhalt ändern will, nutzt weiter `--full`/`--incremental`.
- **Stale-Risiko:** rerender vertraut den On-Disk-Fragmenten. Wenn der User Quellcode geändert hat, ist `--rerender` das falsche Tool (es analysiert nicht neu) — das Precondition-Banner weist darauf hin („für Code-Änderungen `--incremental`/`--full`").
- **No-op-Gate bleibt für die normalen Modi unangetastet** — `--rerender` schaltet ihn nur für sich selbst ab.
- **Emitter (Phase 10 SCA etc.) NICHT neu laufen** — ihre Outputs sind in Fragmente/yaml gebacken (gleiche Regel wie der Re-Render-Loop, `SKILL-impl.md:2008`).

---

## 4. Verifikation (vollständig deterministisch + ein billiger Live-Lauf)

**Deterministisch (CI):**
1. `resolve_config`-Konflikt-Tests: `--rerender` × `{--full,--incremental,--rebuild,--resume}` → Exit 2 (Muster wie bestehende CONFLICTS-Tests).
2. `resolve_config` emittiert `rerender:true`, `mode:"rerender"`, `incremental:false`.
3. Precondition-Gate-Test: leeres OUTPUT_DIR + `--rerender` → Exit 2 mit dem Banner (lässt sich ohne LLM testen, da das Gate vor jedem Dispatch greift — Shell/Python-Pfad).

**Live (ein Lauf, jetzt zuverlässig):**
4. `tests/e2e/run-repair.sh` umstellen: statt `--resume` + Checkpoint-Chirurgie →
   - clean Seed kopieren, §7.2 korrumpieren, **`run-headless.sh --rerender`** (QA an).
   - Erwartung: Renderer recomposed §7.2-Korrumption → QA flaggt `auth_method_decomposition` → Re-Render-Loop dispatcht `appsec-fragment-fixer` → Fix → konvergiert.
   - Asserts (schon im Skript): fixer im Log, §7.2-Heading repariert, auth-Violation gecleart. **Damit feuert M2b live + on-demand** — der bisher fehlende Beweis.

---

## 5. Umfang / Aufwand

- `run-headless.sh`: +1 Passthrough-Flag + Usage-Zeile.
- `resolve_config.py`: +1 arg, +4 Konfliktzeilen, +2 JSON-Felder. (deterministisch getestet)
- `SKILL-impl.md`: +1 Früh-Branch (Gating/Routing, ~20–30 Zeilen Prosa), reine Wiederverwendung von Stage 2/3.
- `run-repair.sh`: von `--resume`/Checkpoint auf `--rerender` umstellen (vereinfacht das Skript).
- Tests: 3 deterministische resolve_config/Precondition-Tests.
- **Risiko: niedrig-mittel.** Der Render+QA+Repair-Flow ist bestehender, getesteter Code; `--rerender` ist Gating davor. Einziges echtes Verhalten-Risiko: dass der Skill-Früh-Branch alle nötigen Config-Vars setzt, die der Stage-2/3-Code erwartet — per Code-Review gegen den `STAGE11_CUTOFF`-Recovery-Pfad (der dasselbe tut) abdeckbar.
