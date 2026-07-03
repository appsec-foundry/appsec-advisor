# Rollout-Plan: Thin/Compact Orchestrator als Default

**Status:** verifiziert am Code (2026-07-03), noch nicht umgesetzt.
**Ziel:** Die compact runtime (`SKILL-full-runtime.md`, via `orchestration_controller.py`) von **opt-in** (`APPSEC_THIN_ORCHESTRATOR=1`) auf **Default mit opt-out** (`=0`) umstellen — aber nur, wenn Parität nachgewiesen ist.

**Ausführung:** neuer Branch off `dev` (nicht `main`/`dev` direkt), targeted test suite + `make check`, **Stop vor Push/Merge** → Summary + Diff. `AGENTS.md` vor nicht-trivialen Änderungen lesen (Contract-/Drift-Regeln). Arbeitsverzeichnis: `/home/mrohr/appsec-advisor`.

---

## Phase 1 — Headless-Completion verifizieren *(zuerst)*

Der Commit `d57d5a3` (2026-07-03) hat einen deterministischen Compose-Backstop `_compose_if_ready()` in `scripts/orchestration_controller.py` eingebaut: wenn Render-Fragmente da sind (`ms-verdict.json` + `security-architecture.md`) aber `threat-model.md` fehlt, komponiert er deterministisch (pregenerate → `compose_threat_model.py --strict` → `apply_prose_fixes` → `qa_checks autofix`). Gerufen über den finalize-`next`-Call (in `SKILL-full-runtime.md §6` mandatory vor jeder completion-summary).

**Offene Verifikations-Aufgabe:** Feuert `_compose_if_ready` auch im headless **bg-ceiling PROZESS-KILL**-Fall (Claude Code terminiert den `-p`-Prozess bei `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=600s`), oder **nur** wenn der Orchestrator noch einen finalize-Turn bekommt (turn-budget / skipped-step)?
- **Wenn nicht abgedeckt:** in `scripts/run-headless.sh` für Headless `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0` **oder** `APPSEC_PARALLEL_RENDER=0` exportieren, und Headless **fail-closed** machen (exit≠0 wenn `threat-model.md` fehlt — aktuell meldet es fälschlich `✓ completed` / exit 0).

## Phase 0 — Parität nachweisen *(hartes Gate, kein Merge-Code)*

Kontrolliertes A/B: **thin vs legacy, gleiches Modell, Repo `/home/mrohr/juice-shop`, gleiche Depth**, je 2–3 Läufe (Varianz-Baseline). YAML vergleichen.

Bereits ~Parität (Vergleich thin `docs/security-thin` vs baseline `docs/security`):
- Threats 53 vs 55, Mitigations 53 vs 55, Komponenten 11 vs 10, Attack-Surface **107=107**, STRIDE alle 6 Kategorien vergleichbar, LLM/AI 5=5, 0 Threats ohne Evidence/Mitigation-Link.

**Der eine offene Punkt — Severity-Drift:** thin **C24/H25/M4** vs baseline **C17/H23/M15**. Thin ist Critical-lastiger. Wahrscheinlich Run-/Modell-Varianz (thin-Subagenten liefen `sonnet-4-6`), NICHT der Orchestrator (er fasst die triage-Logik nicht an). **A/B muss das klären.**

**Gate:** Zeigt das A/B eine echte thin-verursachte Severity-Regression → **NICHT flippen**, Findings berichten, stoppen.

## Phase 2 — Gate flippen *(nur wenn Phase 0 hält; ~10 Zeilen an 4 Stellen)*

1. `scripts/orchestration_controller.py:238` — Gate `APPSEC_THIN_ORCHESTRATOR == "1"` → **`!= "0"`** (opt-in → opt-out).
2. `scripts/orchestration_controller.py:260,262` — `route()`-reason-Strings aktualisieren.
3. `skills/create-threat-model/SKILL.md:68` — Doku „only with `=1`" → „**Default; opt-out via `=0`**".
4. `skills/create-threat-model/SKILL-impl.md:579` — analoge Doku-Anpassung.

**Beibehalten:** alle Special-Mode-Exclusions (`resume`/`dry-run`/`rerender`/`max_cost`/`max_wall`/`LIVE_PHASE`) routen weiter auf Legacy. `APPSEC_THIN_ORCHESTRATOR=0` bleibt als permanenter Escape-Hatch.

## Phase 3 — Tests + Drift

- `tests/test_orchestration_controller.py`: opt-in → opt-out Assertions (Default=thin, `=0`→legacy, special modes→legacy). Den neuen `test_compose_if_ready_*`-Test behalten.
- Changelog-Eintrag; `make check` + targeted subset (CONTRIBUTING.md).

## Phase 4 — Safe Rollout

Escape-Hatch behalten; optional Canary-Phase, bevor der Opt-out-Hinweis aus der Doku verschwindet.

---

**Kontext-Referenzen (Stand 2026-07-03):**
- Thin-Prompt `SKILL-full-runtime.md` = 263 Zeilen vs Legacy `SKILL-impl.md` = 4441 Zeilen (~17× kleiner → weniger cache_read/Turn = der Kostenhebel).
- Router-Logik: `orchestration_controller.py:_runtime_for()` (`:236-245`) + `route()` (`:250-269`).
- Nur 2 Commits haben die Thin-Dateien je berührt (jüngster `d57d5a3`) → Beta, noch in Härtung.
