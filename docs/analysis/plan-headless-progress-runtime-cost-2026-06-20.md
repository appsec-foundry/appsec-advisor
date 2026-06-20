# Plan: Headless-Fortschritt + Laufzeit + Kosten (Analyse, NICHT umgesetzt)

Status: **Analyse-only**, 2026-06-20. Drei Anzeige-Elemente in einem periodischen
Headless-Liner + End-Summary: (1) grober Prozent-Fortschritt, (2) Netto-Laufzeit
(gesamt − Standby), (3) Kosten (tatsächlich + API-äquivalent).

Leitprinzip: **kleine Lösung**. Keine neue Infrastruktur, wo bestehende wiederverwendbar
ist. Alles deterministisches Python im bestehenden 60s-Watchdog-Loop + End-Summary.

---

## Element 1 — Grober Prozent-Fortschritt  (Aufwand: KLEIN, alle Bausteine da)

Bausteine existieren:
- Aktuelle Phase liegt durabel auf Platte: `.appsec-checkpoint` (`phase=<N>`),
  geparst in `acquire_lock.py:181-230` (`_current_phase_label`).
- Periodischer Emitter existiert: `skill_watchdog.py:593-647`, 60s-Loop, kennt Phase,
  ruft `event_log.format_line()`. Neue Zeile additiv, kein Schema-Constraint.
- Gewichtung: ZWEI unabhängige Phasen-Gewichtstabellen existieren (nicht eine!) —
  wählen, nicht vermengen:
  - `data/phase-budgets.yaml` — Wall-Time-Budget je Phase × Depth; gepflegt für
    Watchdog-Stall-Klassifikation. Nur 1/2/3/9/10b/11 explizit, 4–8 = Fallback.
  - `scripts/estimate_duration.py:164` `_PHASE_DURATION` — eigene hartkodierte
    Minuten-Tabelle je Depth, MIT Bruchgewichten (Zeile 451-457: ×0.5/×0.3 für
    Phasen 3–6). Summen-über-Phasen-Pattern existiert dort bereits (Resume-Restzeit).
  - Empfehlung: `_PHASE_DURATION` ist die feinere Basis (deckt 4–8 ab), aber für
    Konsistenz mit Stall-Logik ggf. `phase-budgets.yaml` + Fallback. Eine Quelle wählen.

Berechnung: `pct = Σ(gewicht[erledigte Phasen]) / Σ(gewicht[alle Phasen])`.

Ehrliche Grenzen (warum „ungefähr"):
- Checkpoint-Granularität = ganze Phasen → Wert steht in langen Phasen (v.a. Phase 9
  STRIDE) minutenlang still.
- Phasenliste hartkodiert + VERSTREUT (kein zentrales Enum): `[Phase N/11]`-Echos
  liegen in `appsec-threat-analyst.md` UND 4 phase-group-Docs (phase-group-recon/
  -architecture/-threats/-finalization.md, ~67 Treffer gesamt). (Korrigiert: NICHT
  an `appsec-threat-analyst.md:1154-1319` — diese Zeilenangabe war falsch.)
  `phase-budgets.yaml` listet nur 1/2/3/9/10b/11 explizit; 4–8 teilen
  `unlisted_phase_fallback_seconds` (180s) → bei dieser Tabelle Kurve ruckelt dort
  (bei `_PHASE_DURATION` nicht, da 4–8 dort eigene Werte haben).
- Phase 2.5 konditional (`HAS_IAC_SURFACE`), Inkremental überspringt Phasen →
  Nenner ist lauf-abhängig, nicht konstant.
- **Monoton klemmen** (nie zurückspringen bei Resume/Inkremental).

Optionale Verfeinerung (NICHT für kleine Lösung): Sub-Fortschritt nur dort, wo er
existiert — Phase 2 recon `[k/26]`, Phase 9 `.appsec-progress.json` (`step/step_total`).
Mehr Aufwand pro Phase, geringer Mehrwert für „nur Eindruck". Weglassen.

---

## Element 2 — Netto-Laufzeit (gesamt − Standby)  (Aufwand: KLEIN-MITTEL)

Bausteine existieren:
- Run-Start durabel: `.scan-start-epoch` (geschrieben `SKILL-impl.md:1866`,
  gelesen `run_timing.py:226`). Wall = `now − scan-start-epoch`, trivial.
- **End-Summary rechnet Netto bereits**: `render_completion_summary.py:918` →
  `run_timing.compute_timing(output_dir)` liefert `net_compute_secs`, `wall_secs`,
  `standby_secs`; Standby aus Event-Lücken (`_standby_from_event_gaps`). Rendert
  „Net agent compute" + „Idle / standby". → **Für das Ende ist nichts zu bauen.**

Mid-Run-Lücke (das einzige echte Stück Arbeit):
- Watchdog trackt nur den Peak des *aktuellen* Stalls (`run_idle_peak`), resettet bei
  `RUN_RESUMED`. Es gibt KEINE laufende kumulierte Idle-Summe.
- Zwei Wege:
  - (A, bevorzugt) `run_timing.compute_timing()` mid-run aufrufen — liest dieselben
    Logs/Event-Lücken wie am Ende, autoritativ, eine Quelle. O(N)-Logscan je Tick
    (alle 60s, billig).
  - (B) `.agent-run.log` einmal nach allen `RUN_RESUMED`-Peaks grep'en und summieren.
    Weniger autoritativ als (A); nur wählen, falls (A) mid-run nicht sauber läuft.
- Anzeige: `elapsed 45m23s | netto 38m11s (idle 7m12s)`.

Empfehlung: Weg (A) — vermeidet Doppel-Definition von „Standby" (Watchdog-Peak vs
Event-Gap). Gleiche Zahl mid-run wie am Ende = konsistent.

---

## HARTE ANFORDERUNG (User, 2026-06-20)
Kosten DÜRFEN nur angezeigt werden, wenn sie SICHER sind — `/cost`-genau, nie
geschätzt. Geschätzte Werte (tokens × hand-gepflegte Tabelle bei kaputten Eingaben)
waren in der Vergangenheit immer falsch. Lieber GAR KEINE Zahl als eine falsche.

Korrektur einer Annahme: `/cost` ist KEINE vom Backend abgerechnete Exakt-Zahl. Es
liest dieselben Transcript-`usage`-Blöcke (API-gemeldete, authoritative TOKEN-Zahlen)
× Claude Codes Preistabelle. Es existiert KEINE Kostenzahl, die autoritativer ist als
tokens×Preis — auch `/cost` nicht. Mid-run gibt es kein abgreifbares server-`total_cost_usd`
(nur am Session-Ende im Headless-JSON, für einen laufenden Skill nicht erreichbar).

→ „`/cost`-genau" = dieselbe Quelle wie `/cost` KORREKT lesen: authoritative Usage über
Haupt- + ALLE Sub-Agent-Transcripts, mit korrektem Preis je Modell. Dann per
Konstruktion = `/cost`. Frühere Falschwerte kamen von kaputten Eingaben (trockene
SESSION_STOP-Pipe → unterzählt; Modell pauschal sonnet → falscher Preis; Sub-Agent-
Transcripts separat → lückenhaft aggregiert), nicht vom Konzept tokens×Preis.

DREISTUFIGE ANZEIGE-POLICY (verfeinert 2026-06-20): nicht binär. Unsicherheit ist
messbar — Stufe aus Signal ableiten, nicht raten.

Unsicherheits-Signal (aus vorhandenen Logs):
- `coverage` = Agenten-mit-erfasster-Usage / dispatchte Agenten
  (SESSION_STOP-mit-Usage vs. AGENT_SPAWN in `.hook-events.log`).
- `modell_bekannt` = Modell je Agent aus AGENT_SPAWN `model=` auflösbar.
- `preis_aktuell` = `PRICING_MODELS`-Keys gegen real genutzte Modell-IDs geprüft
  (stale `opus-4-6` vs. Opus 4.8 = nicht aktuell).

Stufen:
1. SICHER (coverage ~vollständig + modell_bekannt + preis_aktuell) → normal anzeigen,
   ehrliches Label „= /cost-Methode". Das ist die Parität-mit-`/cost`-Stufe.
2. ETWAS UNSICHER (eine Bedingung wackelt: Preistabelle evtl. veraltet, vereinzelt
   Agenten ohne Usage) → anzeigen MIT Warnhinweis: `~$X (geschätzt, kann abweichen)`.
3. SEHR UNSICHER (keine/kaum Usage erfasst — aktuell 0 SESSION_STOP; Modelle
   unbekannt) → GAR NICHT anzeigen. Lieber nichts als falsch.

Harte Zusatzregel — MID-RUN immer Stufe 3: noch laufende Agenten tragen 0 bei, jede
Zwischensumme ist ein wandernder Unterzähler → im periodischen Liner NIE Kosten,
unabhängig vom Signal. Nur Element 1 (Prozent) + 2 (Laufzeit). Kosten ausschließlich
in der End-Summary, dort Stufe 1/2/3 nach obigem Signal.

## Element 3 — Kosten: NUR am Ende, NUR /cost-genau  (Aufwand: MITTEL — durch Quelle blockiert)

### Was bereits existiert UND verdrahtet ist
- Pricing-Tabelle: `config.json:7-11` + `verify_run_costs.py:49-68` `PRICING_MODELS`
  (sonnet/opus/haiku, input/output/cache_write/cache_read).
- Berechnung + Banner: `cost_running_total.py` (`aggregate_running_total`,
  `format_banner` → „↳ running total: 45k tokens, $0.18").
- Bereits aufgerufen: `appsec-threat-analyst.md:356` (nach Phase 8, non-fatal),
  `SKILL-impl.md:1742` (Budget-Check). **Der Banner ist also schon im Pipeline-Flow.**
- Modell-Attribution: jede `agents/*.md` Frontmatter `model:`; Dispatch-Override
  geloggt in AGENT_SPAWN (`agent_logger.py:_agent_model`).

### Der echte Blocker (empirisch verifiziert 2026-06-20)
Token-Quelle = `SESSION_STOP`-Zeilen, die der `Stop`/`SubagentStop`-Hook
(`agent_logger.py:handle_stop`, parst `transcript_path`-Usage) schreiben soll.
Hooks sind registriert (`hooks/hooks.json:33-48`).

**ABER: 0 SESSION_STOP in 3 realen Run-Logs** (`/tmp/tm-sonnet-standard`,
`/tmp/tm-phase-d-quick`, `/tmp/tm-verbose-quick`). Vorhandene Events nur:
HEARTBEAT (Watchdog), AGENT_SPAWN (PreToolUse), PHASE_*/SCAN_START (Bash-Echos).
Kein SESSION_STOP, kein PostToolUse-SCAN_COMPLETE, kein BUDGET_*.

→ Stop/SubagentStop/PostToolUse-Hooks feuern in diesen Headless-Läufen nicht (oder
liefern keine Usage). **Aktuell wäre jede Kostenanzeige $0 / n/a.** Die Kosten-Pipe
ist verdrahtet, aber trocken.

Vor Kostenanzeige zu klären (Root-Cause, separate Untersuchung):
- Feuert `SubagentStop` im `claude -p`-Headless-Pfad überhaupt?
- Liefert das Headless-Transcript Usage-Blöcke an den Hook?
- Wird das Plugin (und damit `hooks/hooks.json`) in der juice-shop-Session geladen?
  (Memory `gotcha_env_var_reaches_skill_bash`: cross-project Settings greifen nicht
  immer — analoger Verdacht für Plugin-Hooks.)

### Subscription vs. „was es gekostet hätte"
User läuft auf Subscription → marginaler Real-Cost ≈ $0. Gewünscht ist die
**API-äquivalente hypothetische Summe** = Tokens × Listenpreis. Das ist exakt die
Zahl, die `format_banner` ohnehin liefert. Kein Subscription-Markup-Logik nötig —
nur Label: „API-äquivalent (hypothetisch)". `~$`-Konvention für Subscription ist in
QA/Docs schon vorgesehen (`appsec-qa-reviewer.md`), Berechnung identisch.

→ „Tatsächlich" und „API-äquivalent" fallen für Subscription-User zusammen; sinnvoll
ist EINE Zahl mit Label „hypothetische API-Kosten ~$X (Subscription: real $0)".

---

## Zusammenfassung Aufwand / Reihenfolge

| Element | Bausteine da? | Echte Arbeit | Risiko |
|---|---|---|---|
| 1 Prozent | Phase+Loop+Gewichtung | Helper: budget-summe/checkpoint→pct + 1 Emitterzeile; Phasen 4–8 budgetieren f. glatte Kurve | niedrig |
| 2 Netto-Laufzeit | End-Summary rechnet schon | `compute_timing` mid-run aufrufen + in Liner | niedrig-mittel |
| 3 Kosten | Pricing+Calc+Banner verdrahtet, aber Quelle trocken | NUR am Ende; authoritative Transcript-Usage (Haupt+alle Sub-Agents) × Preis je Modell; Parität-mit-`/cost` garantieren, sonst nichts | hoch — blockiert, MID-RUN ausgeschlossen |

Empfohlene Sequenz wenn umgesetzt wird:
1. Element 1 + 2 zusammen — beide leben im selben Watchdog-Tick, teilen das eine neue
   Liner-Format, null externe Abhängigkeit, KEINE Kostenabhängigkeit. Sofort lieferbar.
2. Element 3 NUR als End-Summary-Feld, separat, NACH:
   (a) Root-Cause warum SESSION_STOP/Transcript-Usage headless nicht aggregiert wird,
   (b) korrekte Preis-je-Modell-Attribution (nicht pauschal sonnet). ACHTUNG Preis-
       Drift: `PRICING_MODELS` (verify_run_costs.py:49-68) hat Keys `opus-4-6`/
       `sonnet-4-6`/`haiku-4-5` — `opus-4-6` ist veraltet ggü. aktuellem Opus 4.8;
       solche stale Keys sind genau die Ursache früherer Falschwerte → Tabelle muss
       gegen tatsächlich genutzte Modell-IDs geprüft werden,
   (c) Nachweis Parität mit `/cost` (gleiche Inputs → gleiche Zahl).
   Bis (a)–(c) bewiesen sind: KEINE Kostenanzeige. Lieber nichts als falsch.

Mid-run-Liner ( OHNE Kosten — nach User-Regel):
```
  ~42%  |  elapsed 45m23s  netto 38m11s (idle 7m12s)
```
End-Summary ergänzt Kosten nach Stufe (siehe Policy oben):
```
  Laufzeit: 45m23s (netto 38m11s, idle 7m12s)
  # Stufe 1: Kosten (API-äquiv, = /cost): $3.10
  # Stufe 2: Kosten (geschätzt, kann abweichen): ~$3.10
  # Stufe 3: Zeile komplett weglassen
```
Laufzeit-Felder am Ende existieren bereits (`run_timing.compute_timing`).
