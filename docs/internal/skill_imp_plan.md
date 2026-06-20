# Umsetzungsplan — SKILL-impl.md für Sonnet-Orchestrierung aufräumen

**Datei:** `appsec-advisor/skills/create-threat-model/SKILL-impl.md`
**Stand Baseline:** 4329 Zeilen / ~346 KB (~86k Tokens)

## Umsetzungsstatus (Branch `feature/skill-impl-sonnet-cleanup`, 2026-06-20)

Umgesetzt wurde der **voll deterministisch verifizierbare** Teil des Plans. Alles, dessen
plan-eigenes Akzeptanz-Gate ein Live-Sonnet-Golden-Run oder Charakterisierungstests sind
(die ich in dieser Umgebung nicht ausführen kann), ist bewusst **nicht blind umgesetzt** —
das gebietet „korrekte Umsetzung sicherstellen".

| Workstream | Status | Beleg / Grund |
|---|---|---|
| **Schritt 0** Diagnose | **n/a** | Kein frischer Sonnet-Run-Hook-Log im Repo → empirische Fan-out-Kollaps-Diagnose nicht möglich; Fixes sind unabhängig valide |
| **Schritt 1 / P1** Abuse-Verifier-MUST-Block | **DONE** (`cf7c13a`) | Vergrabener „ONE message"-Vertrag in lokalen HARD-CONSTRAINT-Block gehoben, spiegelt den bereits starken STRIDE-Block; 245+184 Tests grün |
| P1 STRIDE-MUST-Block | **bereits ideal** | Z. 2124 hatte schon `⚠ HARD CONSTRAINT — ONE MESSAGE` + Negativ-Beispiel; kein Churn (Leitplanke 1) |
| **P5** Mode-Routing-Tabelle | **DONE** (`6bcf2bd`) | Additive Navigations-Tabelle vor Pipeline Overview; per-Sektion-Bedingungen bleiben autoritativ; 295 Tests grün |
| **P7** Verbatim-Subjects-Copy-Block | **bewusst NICHT** | Subjects stehen schon in gebacktickter Bedingungstabelle (Z. 1952), explizit „source of truth"; ein Copy-Block schüfe konkurrierende Zweitquelle (verletzt Leitplanke 3) |
| **P4** pregenerate-Dedup | **bewusst NICHT** | Keine echte Duplikation: 3 Ausführungs-Sites, 2. Aufruf divergent (`+_chain-skeleton.md`); Dedup zu kanonischer Referenz verletzt R3 |
| **P4** Marker-Lifecycle | **Befund dokumentiert, nicht ausgeführt** | Sektion „Verbose Mode — Marker File Lifecycle" existiert 2× (Z. ~699 `$VERBOSE_REPORT` vs. 863 `RESOLVED_JSON`); **863 ist autoritativ** (EXIT-Trap + Tracing-Sibling), `VERBOSE_REPORT` wird nirgends im Bash zugewiesen → ~706er Touch ist wahrscheinlich toter Code. Konsolidierung ist Code-Änderung, plan-Gate = „Golden-Run --verbose UND ohne" → nicht ausführbar hier |
| **P8** Lazy-Load Mode-Sektionen | **gated** | Akzeptanz = Golden-Run je Modus (full+incremental+rerender); + `SKILL.md`-„in full"-Lockerung + `required-permissions.yaml` (L3) |
| **P3** Shell→`.sh` | **gated** | Akzeptanz = Charakterisierungstests + Golden-Run; höchstes Drift-Risiko |
| **Schritt 2** Live-Sonnet-Golden-Run | **TEILWEISE — Kern bestätigt 2026-06-20** | `/model sonnet`-Lauf (standard, juice-shop `455206c32`) gefahren: **alle drei Fan-outs unter Sonnet parallel, kein Kollaps** — STRIDE 7 Komp. in 64 s, **Abuse-Verifier (P1-Edit) 6 in 7 s**, Parallel-Render 2 in 4 s. Followability-Primärziel live erreicht. **Offen:** voller Completion-DoD (Stage 3 QA + Abschluss) + YAML-Struktur-Diff vs. Baseline. Surfaced (pre-existing, nicht vom Refactor): `event_log.format_line()` Arg-Mismatch + Recon-Inline-Fallback |

**Verifikation des Umgesetzten:** volle Suite **8376 passed / 55 skipped / 0 failed**;
`make lint` sauber bis auf vorbestehende Format-Drift in `tests/test_scan_excludes.py`
(nicht von diesen Commits berührt). Drei reviewbare Einzel-Commits.

**Nächster Schritt für den Nutzer:** Schritt 2 fahren — ein `/model sonnet`-Lauf gegen
Juice Shop. Bestätigt der parallelen Fan-out + Strukturgleichheit zur Opus-Baseline, ist das
Primärziel erreicht (Plan-Stopregel). Erst danach lohnen P4-Code/P8/P3.

## Ziel

Der Skill soll **zuverlässig von Sonnet** (statt nur Opus) als Orchestrierer ausgeführt
werden können. Primärziel ist **Instruktions-Befolgbarkeit für ein schwächeres Modell**,
nicht Token-Sparen. Niedrigere Orchestrierungskosten (weniger Kontext pro Turn,
~5× günstiger auf Sonnet) sind willkommener Nebeneffekt, nicht der Treiber.

Kernhypothese: Sonnet scheitert an dieser Datei nicht an der reinen Größe, sondern daran,
dass **Verträge verstreut, implizit und in Rationale vergraben** sind und **Verzweigungen
als Prosa statt als Tabellen** vorliegen. Aufräumen = jede Anweisung explizit, lokal,
tabellarisch machen und fragile Inline-Shell entfernen.

## Leitplanken (gelten für JEDEN Schritt)

1. **Byte-identisches Laufzeitverhalten.** Kein Gate entfernen, keine Exit-Codes ändern.
   Ein Diff darf nur Umformung zeigen, keinen geänderten Befehl.
2. **Erfolgstest = Sonnet-Golden-Run.** Akzeptanzbedingung pro Phase ist ein
   `/model sonnet`-Lauf gegen OWASP Juice Shop, der sauber durchläuft (korrekte Fan-out-
   Parallelität, alle Gates, korrekte Stats, keine übersprungenen Schritte). Zusätzlich
   Struktur-Diff von `threat-model.yaml`/`.md` + `.stage-stats.jsonl` + Gate-Exit-Codes
   vor/nach.
3. **Lokale statt globale Verstärkung.** Verträge EINMAL, direkt am Ausführungspunkt, als
   expliziter „MUST"-Block — nicht 5× über die Datei verteilt. Das hilft einem schwachen
   Modell mehr als verstreute Wiederholung.
4. **Chesterton's Fence.** Rationale, die eine Logik *schützt* (warum eine Abkürzung
   falsch ist), wird nicht gelöscht, sondern ko-lokalisiert (Skript-Docstring) oder knapp
   inline belassen — nie pauschal entfernt.
5. **Inkrementell, kein Big-Bang.** Pro Workstream ein eigener, reviewbarer Commit + Test.
6. **Cache-stable prefix respektieren.** Der Skill-Body wird pro Turn als Cache-Read
   serviert; Einfügungen/Umordnungen nahe am Dateianfang invalidieren den stabilen Prefix
   und können Cache-Misses *erhöhen* statt senken (AGENTS.md:186 Group-A→B→C-Disziplin).
   Additive Änderungen unterhalb des stabilen Prefix; Byte-Offset-Verschiebung durch
   Extraktion gegen Cache-Verhalten prüfen, nicht nur gegen Exit-Codes.

## Verifizierte Baseline (Belege, Stand 4329 Zeilen)

| Befund | Messung | Punkt |
|---|---|---|
| Meta-Narration-Suppression wiederholt | 28 Treffer (`narrat`/`suppress`) | P1 |
| „single/ONE message"-Fan-out-Vertrag | 6 Treffer, verstreut | P1 |
| TaskStop-Schema-Lade-Hinweis | 12 Treffer | P1 |
| `verbatim`-Anforderungen | 18 Treffer | P7 |
| Verzweigungs-Exits | 40× `exit 2/3` | P2 |
| Branch-Variablen (GATE_EXIT/CUTOFF/DECISION) | 55 Referenzen | P2 |
| Inline-Bash-Fences | 69 | P3 |
| `python3 -c`-Einzeiler | 52 | P3 |
| Heredocs | 13 | P3 |
| pregenerate-Block dupliziert | 3× (Z. 2753 / 3269 / 3338) | P4 |
| Marker-Lifecycle dupliziert (Code DIVERGENT) | 2× (Z. 706 `$VERBOSE_REPORT` vs. 875 `RESOLVED_JSON`) | P4 |
| Mode→Sektion-Routing-Tabelle | existiert NICHT (nur verstreute „SKIP …"-Prosa, z. B. Z. 904) | P5 |
| Historische Rationale-Marker | 131 (M2/M3, Daten, Sprint, RC, G/DG) | P6 |
| TaskCreate-Subjects | als verbatim-Pflicht definiert ab Z. 1946 | P7 |
| Mode-spezifische Top-Level-Sektionen (nie im Full-Run) | 597 Z. = 13,8 % (Re-Render 32, Incr-Pre-Check 37, Incr-Fast-Path 298, Full-Scan-Prompt 119, Resume 79, Incr-Mode 20, Dry-Run 12) | P8 |
| `SKILL-impl.md` wird „in full" geladen (Wurzel: defeats jede in-file-Lazyness) | `SKILL.md` Case-2-Anweisung | P8 |
| Lazy-Load existiert bereits (phase-group, gepinnt) | 4 Dateien / ~6000 Z., JIT an Phasengrenzen, `test_lazy_phase_group_loading.py` | P8 |

## Workstreams

### P2 — Verzweigungen: Prosa → Entscheidungstabellen (zuerst)
**Problem:** 40 `exit 2/3`-Pfade, 55 Branch-Variablen-Referenzen; Branch-Logik in
mehrabsätziger Prosa. Schwaches Modell wählt unter Last den falschen Zweig.
**Aktion:** Jede Verzweigung als kompakte Tabelle `Bedingung / Exit-Code → genau dieser
Schritt`. Betrifft v. a. die Stage-3-Gate-Branches (GATE_EXIT 0/1/2/3), die Cut-off-
Klassifikation (STAGE1_CUTOFF / STAGE1_CUTOFF_NO_STRIDE / STAGE11_CUTOFF), die
Pre-Check/Dirty-Set-Verdikt-Matrix.
**Risiko:** niedrig — reine Umformung, keine Logikänderung.
**Verifikation:** Diff zeigt nur Tabellen statt Prosa; Exit-Codes unverändert.

### P7 — Verbatim-Strings als Copy-Blocks (zuerst)
**Problem:** 18× „verbatim"-Pflicht (v. a. die 8 TaskCreate-Subjects); ein schwaches
Modell paraphrasiert trotzdem → spätere `TaskUpdate` no-oppen, Spinner hängt.
**Aktion:** Die exakten 7–8 Subject-Strings als ein einziger Copy-Code-Block direkt am
Bootstrap-Schritt; Prosa-Erklärung daneben kürzen.
**Risiko:** niedrig — reine Umformung.
**Verifikation:** Subjects unverändert; Golden-Run: alle Stage-Tasks erreichen `completed`.

### P4 — Divergente Duplikate auf eine Quelle reduzieren
**Problem:** pregenerate 3×; Marker-Lifecycle 2× mit **unterschiedlichem** Code.
**Aktion:**
- pregenerate: **ACHTUNG — keine vollständige Identität (per Diff verifiziert 2026-06-20).**
  An den 3 Stellen (Z. ~2751 / ~3267 / ~3336) stehen je ZWEI Aufrufe. Der erste
  (`--force --only system-overview…attack-walkthroughs.md`) IST über alle drei identisch →
  kanonisierbar. Der zweite ist NICHT identisch: Z. 2760 = `--only security-architecture.md`,
  Z. 3271/3340 = `--only security-architecture.md,_chain-skeleton.md` (Stage-2 vs.
  Recovery-Pfad). Nur den Force-Block dedupen; den zweiten Aufruf als eigenständig behandeln,
  sonst geht `_chain-skeleton.md` verloren bzw. wandert an die falsche Stelle.
- Marker-Lifecycle: **zuerst klären, welcher Code-Block maßgeblich ist** (Z. 706 hängt an
  `$VERBOSE_REPORT`, Z. 875 leitet aus `RESOLVED_JSON` ab — NICHT identisch). Eine Fassung
  als kanonisch festlegen, die andere entfernen. Prosa/Überschrift sicher zusammenführbar;
  Code-Konsolidierung mit Vorsicht.
**Risiko:** Prosa-Dedup niedrig; Marker-Code-Konsolidierung mittel (erst Autorität klären).
**Verifikation:** Golden-Run mit `--verbose` UND ohne — Marker-Datei-Verhalten identisch.

### P5 — Mode-Routing-Tabelle ganz oben
**Problem:** Keine Routing-Tabelle; incremental/rerender/resume/rebuild-Logik wird beim
Standard-Full-Run linear mitgelesen. Schwaches Modell verliert den Faden.
**Aktion:** Additive Tabelle am Dateianfang: `MODE=full/standard → lies Abschnitte X–Y,
überspringe Z; incremental → zusätzlich …; rerender → Abschnitt R`. Entfernt nichts.
**Risiko:** ~null (rein additiv).
**Verifikation:** Diff zeigt nur Hinzufügung; kein bestehender Abschnitt verändert.

### P1 — Verstreute Verträge an den Ausführungspunkt holen
**Problem:** Kritische Regeln verstreut/wiederholt (Meta-Narration 28×, Fan-out „one
message" 6×, TaskStop-Schema 12×, write-first). Schwaches Modell droppt sie unter Last.
**Aktion:** Pro Aktion ein kompakter **„MUST"-Block direkt davor** (3–5 Imperative). Regel
*lokal einmal* statt global verteilt:
- Fan-out: „MUST" direkt am STRIDE- und am Abuse-Verifier-Dispatch.
- TaskStop-Schema-Load: einmal am ersten TaskStop, Referenz an den späteren.
- Meta-Narration-Suppression: einmal kompakt oben, nicht 28× wiederholen.
**Risiko:** mittel — Redundanzabbau kann Adhärenz schwächen; via *lokaler* Verstärkung
abgefedert (Leitplanke 3).
**Verifikation:** Sonnet-Golden-Run: Fan-out wirklich parallel (≥N `AGENT_SPAWN` in einer
Runde), kein TaskStop-Param-Fehler, keine Meta-Narration im Output.

### P6 — Imperativ zuerst, Rationale knapp/ko-lokalisiert
**Problem:** 131 Incident-/Versions-Marker verwässern, *was zu tun ist*.
**Aktion:** Operativer Satz zuerst; „Warum" in den Skript-Docstring (bei P3-Extraktion) oder
als knappe Klammer. Nicht löschen (Chesterton). Reine Flow-Historie ohne Skript-Heimat als
knappe CHANGELOG-Notiz, nicht im Anweisungsfluss.
**Risiko:** mittel (Chesterton) — Pointer-Token am Ort belassen.
**Verifikation:** Diff zeigt nur verschobene Prosa; jeder Befehl unverändert.

### P3 — Fragile Inline-Shell durch Skript-Aufrufe ersetzen (zuletzt, höchster Wert)
**Problem:** 69 Bash-Fences, 52 `python3 -c`, 13 Heredocs; verschachteltes Quoting
(Deadline-Blob). Genau die Stellen, an denen ein schwaches Modell Quotes/Variablen
korrumpiert.
**Aktion:**
- **Charakterisierungstests ZUERST** (Golden-Inputs → Outputs/Exit-Codes/Dateien),
  ohne den Skill zu ändern. Voraussetzung für jede Extraktion.
- Die 3 großen Brocken **verbatim** auslagern (Bash→`.sh`, nicht Bash→Python-Rewrite, um
  Reimplementierungs-Drift zu vermeiden): Deadline-Watchdog, Wipes, Completion-Persistenz.
  Im Skill nur noch `bash scripts/x.sh "$ARG"`.
- Off-Path-Blöcke (Deadline, Session-/Cache-Detektoren) sind per Standard-Golden-Run NICHT
  abgedeckt → zwingend synthetische Fixture-Tests.
- Die ~52 `python3 -c`-Einzeiler NICHT einzeln extrahieren (Overhead > Nutzen); nur dort
  konsolidieren, wo sie sich wiederholen (z. B. das `mtime:size`-Snapshot-Muster).
**Risiko:** höchste der Liste — neues Arg-Interface, Drift erst einen Lauf später sichtbar
(v. a. Net-Wall-Vergleich / baseline.json-Merge → Standby-Miscount-Klasse).
**Verifikation:** Charakterisierungstest (alt vs. neu identisch) + Golden-Run.

### P8 — Mode-spezifische Sektionen lazy laden (struktureller Hebel, statt in-place komprimieren)
**Problem:** `SKILL.md` weist an, `SKILL-impl.md` **„in full"** zu lesen → die ganze Datei
ist jeden Lauf, in jedem Modus, resident. **597 Z. (13,8 %)** sind mode-spezifische
Top-Level-Sektionen (incremental/rerender/resume/dry-run), die ein Standard-Full-Run nie
ausführt, aber mitliest. Folge: ein schwaches Modell trägt 14 % irrelevanten Kontext, in
dem es den Faden verlieren kann; P5 (Routing-Tabelle) lenkt nur die *Aufmerksamkeit* um,
entfernt aber **keine Bytes** — sie sind durch „in full" längst geladen.
**Schlüssel:** Das Repo hat den Mechanismus bereits — `agents/phases/phase-group-*.md`
werden JIT an Phasengrenzen geladen (gepinnt in `test_lazy_phase_group_loading.py`,
AGENTS.md:186). P8 wendet dieses bewährte Muster auf den Skill-Body an.
**Aktion:** Mode-spezifische Sektionen aus `SKILL-impl.md` in eigene, an der
Mode-Verzweigung JIT geladene Dateien migrieren (z. B. `modes/incremental.md`,
`modes/rerender.md`, `modes/resume.md`); `SKILL-impl.md` bleibt als dünnes Full-Run-Rückgrat.
Die Mode-Routing-Tabelle aus P5 wird dann zur *Lade*-Tabelle (welche Datei wann), nicht nur
zur Lese-Hinweis-Tabelle. **`SKILL.md`'s „in full"-Anweisung muss entsprechend gelockert
werden** — sie ist die eigentliche Wurzel.
**Abgrenzung zu R3:** Operative Verträge am Dispatch-Punkt bleiben INLINE (Leitplanke 3).
Ausgelagert werden nur *mode-conditional Bodies* — genau die Klasse, die phase-group bereits
erfolgreich out-of-line hält. R3 verbietet das NICHT (siehe geschärftes R3).
**Risiko:** niedrig–mittel — kein neues Arg-Interface (anders als P3), wiederverwendet
gepinnten Loader; Hauptconstraint = cache-stable prefix (Leitplanke 6): Auslagerung muss an
Mode-Grenzen unterhalb des stabilen Prefix sitzen.
**Verifikation:** Golden-Run je Modus (full + mindestens incremental + rerender) lädt die
richtige Datei zur richtigen Zeit; Full-Run-Kontext nachweislich um ~597 Z. kleiner;
phase-group-Lazy-Load-Tests bleiben grün; Mode-Läufe strukturidentisch zur Baseline.

## Erwarteter Gewinn (Token / Zeit / Kosten)

**Kernbefund: Token-/Kostenersparnis und Risiko sind korreliert.** Die billigen,
sicheren Maßnahmen sparen fast nichts; die Ersparnis steckt in den riskanteren.

### Token-Effekt je Maßnahme

| Maßnahme | Token-Effekt | Risiko |
|---|---|---|
| **P3** Inline-Shell → Skript | **stark −** (größter Hebel) | hoch |
| **P8** Mode-Sektionen lazy laden | **stark −** für Full-Run (~597 Z. / 13,8 %) | niedrig–mittel |
| **P6** Rationale aus dem Fluss | mittel − | mittel |
| **P1** Verträge lokal-einmal | mittel − | mittel |
| **P4** Dedup | leicht − | niedrig–mittel |
| **P2** Tabellen | ~neutral | niedrig |
| **P7** Copy-Blocks | ~neutral | niedrig |
| **P5** Routing-Tabelle | leicht **+** (additiv) | ~null |

Folge: Das risikoarme Bündel **P2+P4+P5+P7 ist praktisch token-neutral** — sein Wert
ist Followability, nicht Größe. Echte Ersparnis nur aus **P3/P6/P1** — und aus **P8**, das
für den Full-Run einen P3-vergleichbaren Byte-Gewinn (~597 Z.) bei deutlich geringerem
Risiko liefert (kein Arg-Interface, gepinnter Loader). **P5 und P8 sind komplementär:**
P5 ohne P8 senkt keine Tokens (Datei wird „in full" geladen), erst P8 macht die
Routing-Tabelle zur Lade-Entscheidung.

### P3 — konkrete Messung (Baseline 4330 Zeilen)

- **86 Bash-Blöcke, 2081 Zeilen = 48 % der Datei** stecken in Bash-Fences.
- Extraktionskandidaten (>20 Zeilen): **30 Blöcke = 1657 Zeilen.**
- Größte Brocken: Auto-Emitter-Pass 138 Z. (sauberster 1:1-Fall), Pre-flight-Recovery
  126 Z., Completion-Persistenz 98 Z., Recommendation-Prompt 97 Z., YAML-Gate 95 Z.,
  STAGE11-Recovery 90 Z., Session-Detektor 88 Z., Deadline-Watchdog 66 Z.
- **Ersparnis P3:** aggressiv ~1550 Zeilen (~36 %, ~20–25k Tokens, ~23–29 % des Prompts);
  konservativ ~700–900 Zeilen (~16–21 %, ~10–13k Tokens). Realistisch **~700–1550 Zeilen
  / ~10–25k Tokens** — mit Abstand der größte Einzelhebel.
- Vorbehalt: nur *Prompt*-Ersparnis — die ausgelagerten Skripte laufen weiter, ihre
  **Laufzeit ändert sich nicht**. Var-setzende/interaktive Blöcke schrumpfen nicht 1:1.

### Kostenübersetzung

Der Skill-Body wird pro Turn als Cache-Read neu serviert → eine Prompt-Kürzung um
~15–29 % senkt die Orchestrierungs-Cache-Reads etwa proportional. Auf den Opus-Anteil
(~$20/Lauf gemessen) ⇒ grob ~$3–6 weniger; auf Sonnet ~$0.60–1.20. **Der dominante
Kostenhebel bleibt der Wechsel auf eine Sonnet-Session (~5×)** — durch das Aufräumen erst
sicher nutzbar; die P3-Kürzung ist sekundär dazu.

### Zeit-Effekt (asymmetrisch)

- **Unberührt (Großteil der Wall-Clock):** Analyse-Compute (STRIDE/Merge/Render);
  gemessen ~53 min Wall / ~84 min Compute — von keiner Aufräum-Maßnahme beeinflusst.
- **Direkt klein:** kleinerer Kontext → niedrigere Per-Turn-Latenz über ~30 Turns
  (Quelle = P3/P6/P1).
- **Indirekt groß, aber asymmetrisch (meist 0, gelegentlich riesig):** Followability
  (P2/P5/P7/P1) verhindert vergeudete Retry-Turns und — der große Posten —
  Mis-Orchestrierung: kollabierter Fan-out kostet **+22 min** (27 statt 5 min, dokumentiert),
  ein fehlgeschlagener Lauf **+~1 h** (Neustart).
- **Stärkster Zeit-Hebel:** Sonnet generiert pro Turn schneller als Opus — Modellwechsel,
  durch das Aufräumen ermöglicht, keine Datei-Maßnahme selbst.

## Empfohlene Umsetzung (konkret, value-gewichtet)

Verfeinerung gegenüber reiner Risiko-Sortierung: Der **größte Sonnet-Hebel ist die
Verhinderung des seriellen Fan-out-Kollaps** (~+25–35 min vermieden) — das ist zugleich
risikoarm (reine Umformung). Daher steht es vorne, nicht das generische Text-Bündel.

**Schritt 0 — Erst diagnostizieren (gratis, kein Risiko). NICHT refactoren, bevor die
Ursache belegt ist.**
Aus dem *langsamen Sonnet-Lauf* die `AGENT_SPAWN … stride`-Zeitstempel in
`.hook-events.log` prüfen:
- gestaffelt → serieller Fan-out-Kollaps bestätigt → Schritt 1 lohnt.
- gleichzeitig → Ursache ist Session-Bloat (`cache_read` am letzten `SESSION_STOP`,
  Schwelle 8M) oder ein Stall → zuerst `/clear`, **kein** Refactor.

**Schritt 1 — Der eine hochwertige Fix: P1+P2 am Fan-out.**
Die zwei „eine Message, alle N"-Verträge (STRIDE-Dispatch UND Abuse-Verifier) in einen
kompakten, lokalen **„MUST"-Block direkt am Dispatch** umschreiben — explizite Checkliste
statt Fließtext, mit Negativ-Beispiel („NICHT: Agent 1 abwarten, dann Agent 2"). Risiko
~null, trifft den einzigen großen Zeit-Swing. **Wenn nur eine Sache gemacht wird, dann
diese.**

**Schritt 2 — Billig validieren (Akzeptanz-Gate).**
Golden-Run mit `/model sonnet`. Erfolg = STRIDE-Spawns nahezu gleichzeitig + Lauf
strukturell identisch zur Opus-Baseline. **Ist das grün, ist das Primärziel erreicht —
hier darf man aufhören.**

**Schritt 3 — Restliches risikoarmes Bündel (nur wenn Schritt 2 bestätigt).**
P7 (Verbatim-Subjects als Copy-Block), P4 (Dedup — Marker-Block erst Autorität klären),
P5 (Mode-Routing-Tabelle oben). Alle diff-verifizierbar, byte-identisch. Kleiner
Zusatznutzen, weiter sinkendes Fehlerrisiko.

**Schritt 4 — P8: mode-spezifische Sektionen lazy laden (followability-erster Struktur-Hebel).**
~597 Z. (13,8 %) aus dem residenten Full-Run-Kontext nehmen, indem mode-spezifische
Sektionen in JIT-geladene `modes/*.md` wandern (Wiederverwendung des gepinnten
phase-group-Loaders, `SKILL.md`-„in full" entsprechend lockern). Dient direkt dem
Primärziel (weniger residenter Kontext für ein schwaches Modell) bei niedrig–mittlerem
Risiko — **vor** P3, weil kein neues Arg-Interface und kein Reimplementierungs-Drift.
Verifikation: Golden-Run je Modus (full + incremental + rerender) lädt korrekt; phase-group-
Tests grün.

**Schritt 5 — P3 nur, wenn Kosten/Größe eigenständig gewollt sind.**
Shell-Extraktion, **Charakterisierungstests zuerst**, **verbatim Bash→`.sh`** (kein
Python-Rewrite), größter Block zuerst (Auto-Emitter 138 Z. → 1). Höchster Token-Gewinn
(~10–25k), aber riskantester Schritt — zuletzt, nur nach bewiesener Followability.
P6 (Rationale) wird hier als Nebenprodukt der Extraktion mitgezogen (in Skript-Docstrings).

**Entscheidungsregel:** Nach Schritt 2 stoppen, wenn das Ziel „Sonnet zuverlässig" war.
Schritt 3 (risikoarmes Bündel) + Schritt 4 (P8) bringen Followability/Größe bei geringem
Risiko; Schritt 5 (P3) nur, wenn zusätzlich maximale Kosten-/Größenreduktion gewünscht ist.

## Sofort-Hebel ohne Refactor (heute nutzbar)

Unabhängig vom Plan: Scan aus einer **Sonnet-Session mit vorherigem `/clear`** starten →
~5× günstigere und schnellere Orchestrierung sofort. Opus nur behalten, wenn ein Lauf
groß / erstmalig / recovery-anfällig ist (dort kauft Opus Zuverlässigkeit). Schritt 1 des
Plans macht genau diesen Sonnet-Default *sicher*; den `/clear`-Effekt gibt es schon vorher.

## Akzeptanzkriterien (Definition of Done)

- **Primär:** Ein vollständiger Lauf mit Orchestrierer = **Sonnet** läuft sauber durch:
  parallele STRIDE-Fan-out (nicht seriell), alle Gates greifen, korrekte `.stage-stats`,
  keine übersprungenen Schritte, keine Meta-Narration, kein TaskStop-Param-Fehler.
- **Verhalten:** `threat-model.yaml`/`.md`-Struktur, Findings-Zahlen, Gate-Exit-Codes
  byte-/struktur-identisch zu einem Opus-Baseline-Lauf vor dem Refactor.
- **Sekundär:** Messbar niedrigere Orchestrierungs-Tokens/Kosten pro Lauf.
- Pro Workstream grüner Test + reviewbarer Einzel-Commit.

## Offene Lücken / vor Umsetzung zu klären

Sieben konkrete Auslassungen, belegt gegen den Code-Stand 2026-06-20. Nach Wert sortiert.
**L1+L2 zusammen sind die wichtigsten — sie ändern die Validierungs-Ökonomie des ganzen
Plans** (von ~$30/1h pro Phase auf Sekunden) und machen alles Übrige erst zumutbar.

**L1 — Billige Regressionsprüfung existiert; der Plan ignoriert sie (korrigiert R1).**
Mehrere Testdateien pinnen `SKILL-impl.md`-Inhalt: `test_skill_composition_split.py`,
`test_check_inline_shortcut.py`, `test_incremental_mode.py`, `test_help_file.py`,
`test_skill_auto_retry.py`, `test_integration.py`. Jede Umformung (P2/P5/P7) und jede
Auslagerung (P8) bricht diese Tests → sie sind im Gleichschritt zu updaten (CLAUDE.md §4,
bidirektionale Verträge). **Nachzutragen:** pro Workstream eine Zeile „welche Testdatei
pinnt diesen Text". Das — nicht der Golden-Run — ist das Pro-Phase-Akzeptanz-Gate.

**L2 — Deterministische Gates sind der Followability-Orakel; ungenutzt.**
~13 Gates messen, ob der Orchestrierer das Richtige tat: `check_stride_dispatch.py`
(Fan-out wirklich parallel), `validate_dispatch_manifest.py`, `check_inline_shortcut.py`,
`requirements_gate.py`, `qa_release_gate.py`. **Nachzutragen:** je Followability-Eigenschaft
den prüfenden Gate benennen und **N≥3 Sonnet-Läufe gegen die Exit-Codes** als Reliability-
Signal setzen (statt „1 Golden-Run struct-identisch", was für ein Zuverlässigkeitsziel zu
dünn ist).

**L3 — `data/required-permissions.yaml`-Updates für P3 und P8 (Non-Negotiable, AGENTS.md §7).**
P3 führt `bash scripts/x.sh` ein → Bash-Eintrag nötig. P8 führt `Read(modes/*.md)` ein →
verifizieren, ob `Read(${PLUGIN_ROOT}/**)` das bereits deckt (nicht annehmen). Der Plan
erwähnt die Datei nirgends.

**L4 — Kostenbeleg nicht operationalisiert, obwohl Werkzeug existiert.**
DoD „messbar niedrigere Tokens" ohne Wie. Es gibt `scripts/measure_run.py`,
`scripts/verify_run_costs.py`, `scripts/cost_running_total.py`, `cache_read` in
`agent_logger.py`. **Nachzutragen:** Baseline mit `measure_run.py` vor Refactor, gleiches
nach P8/P3, Orchestrierungs-Cache-Reads vergleichen — sonst ist die 15–29 %-/$3–6-Rechnung
unfalsifizierbar.

**L5 — Recovery/Resume unter schwächerem Modell ist UNGETESTET (die Pfade mit MEHR Last).**
Resume-from-Checkpoint, STAGE11-Recovery, Cut-off-Handling, Pre-flight-Recovery werden von
einem schwächeren Modell *häufiger* aktiviert, nicht seltener. Der Plan behandelt sie nur
als „P3 off-path → Fixtures". **Nachzutragen:** ein Sonnet-Lauf, der Kill+Resume/Recovery
erzwingt — nicht nur der saubere Durchlauf.

**L6 — Kein Shipping-Mechanismus für „Sonnet-Default".**
Primärziel „Sonnet zuverlässig" ohne Auslieferungsweg. „Sofort-Hebel" sagt nur „starte eine
Sonnet-Session" — keine durable Config, kein Flag, kein Fallback (großer/recovery-anfälliger
Lauf → Opus). Sonst alles über env-vars/`resolve_config.py` gegated. **Zu klären:**
dokumentierte Guidance, Profil-Schalter oder automatischer Tier-Fallback?

**L7 — Workstreams an grep-Counts statt an belegte Failures gehängt.**
„28× Narration / 12× TaskStop / 6× Fan-out" verknüpft keinen Count mit einem beobachteten
Defekt. Dokumentierter Failure-Katalog existiert: `bug_stride_inline_shortcut`,
`bug_stride_dispatch_gate_blind_in_parallel`, `bug_budget_flag_poisons_renderer`,
`bug_substep2_schema_drift`. **Nachzutragen:** jeden Workstream an einen belegten
Failure-Modus binden (z. B. „P1-Fan-out adressiert `bug_stride_inline_shortcut`") — sonst
optimiert der Plan nach Häufigkeit, nicht nach Schaden.

## Risiken & Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| **R1** Golden-Run teuer (~$30/~1h) UND statistisch dünn (1 Lauf beweist keine Zuverlässigkeit) | **Billiges Substrat existiert** (Lücke L1/L2): die `SKILL-impl`-pinnenden Testdateien + die deterministischen Gates (`check_stride_dispatch`/`validate_dispatch_manifest`/`check_inline_shortcut`/`requirements_gate`) als primäres Per-Phase-Gate; Golden-Run nur als finaler N≥3-Smoke, nicht als Pro-Phase-Gate |
| **R2** Redundanzabbau schwächt LLM-Adhärenz | Lokale Verstärkung am Ausführungspunkt statt globaler Wiederholung |
| **R3** Cross-File-Referenzen werden unter Kontextdruck nicht geladen | Gilt nur für **operative Verträge am Dispatch-Punkt** (MUST-Blöcke INLINE). KEIN pauschales Auslagerungsverbot: phase-group-Dateien lagern phasen-/mode-gescopte Instruktionen bereits erfolgreich aus (gepinnt). Auslagerbar: Rationale/Historie (P6) + mode-conditional Bodies (P8). NICHT auslagerbar: Verträge, die am Ausführungspunkt gelesen werden müssen. |
| **R4** Chesterton — verlorene Schutz-Rationale | Pointer-Token am Ort; Rationale in Skript-Docstring ko-lokalisieren |
| **R5** Extraktions-Drift (Exit-Codes/Quoting/JSON-Merge) | Verbatim Bash→`.sh` statt Python-Rewrite; Charakterisierungstest alt==neu |
| **R6** Off-Path-Blöcke vom Golden-Run nicht abgedeckt | Synthetische Fixture-Tests für Deadline/Detektoren |
| **R7** Divergente Duplikate falsch zusammengeführt | Vor Dedup Identitäts-Diff; bei Marker-Block erst Autorität klären |

## Nicht-Ziele (Scope-Grenzen)

- Keine funktionale Änderung an Pipeline, Gates oder Output-Schema.
- Kein Entfernen von Sicherheits-Gates oder Recovery-Pfaden.
- Kein Big-Bang-Rewrite; keine Aufteilung der **operativen Verträge** über Dateigrenzen
  (P8 lagert nur mode-conditional Bodies aus, keine Dispatch-Punkt-Verträge — siehe R3).
- Keine Modell-Routing-Änderung der Analyse-Sub-Agenten (die sind unabhängig vom
  Session-Modell bereits auto-geroutet).
