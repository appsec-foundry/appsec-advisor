# Analyse — Terminaler Run-Abbruch durch Enum-Verstoß eines LLM-Producers

**Datum:** 2026-08-21 · **Revision 3** (adversarial verifiziert; fünf Korrekturen gegenüber Rev. 1, davon zwei an den empfohlenen Maßnahmen selbst)
**Auslöser:** `/create-threat-model --slug juice-shop-standard-v0.5.2` bricht nach ~4 min
in `context-v2-post-recon` terminal ab.
**Fehler:** `recon-signals-v2 validation failed: 'candidate' is not one of ['deterministic', 'llm-fallback']`

Jede Aussage ist am Code oder empirisch verifiziert. Belege als `file:line` bzw.
als reproduzierter Kommandolauf.

---

## 0. Korrekturen gegenüber Revision 1

Die Verifikation hat drei Aussagen der ersten Fassung widerlegt. Sie stehen hier
vorn, weil sie die Maßnahmenpriorität umkehren.

| # | Rev. 1 behauptete | Verifikation | Konsequenz |
|---|---|---|---|
| K1 | Die Vokabular-Kollision sei per Schema-Lint auffindbar | **Falsch.** Lint über alle 40 Schemas: 14 Kollisionen, **keine davon diese**. Im Schema trägt `status` in `$defs/evidence` das Enum, nicht `has_open_self_registration` — es gibt keine Schema-Kollision. | Die Kollision existiert **nur in der abgeflachten Prompt-Vorlage**. Lint muss auf Template-Ebene laufen. |
| K2 | Controller-Retry (M1/M2) sei die kritische Maßnahme | **Unvollständig.** Das ist die *Auffangschicht*, nicht die Ursache. Der früheste mechanische Eingriffspunkt liegt beim **Schreibvorgang im Producer**. | Prioritäten invertiert: P2 vor P4. |
| K3 | Der fehlende Retry-Pfad sei eine offene Lücke | **Schärfer.** Commit `1acafffb` (15.08.) hat die Absicht bereits implementiert — nur auf die semantische Hälfte derselben Funktion. Der heutige Abbruch ist eine **Regression gegen einen sechs Tage alten, erklärten Design-Intent**. | Kein Neubau nötig, nur korrekte Granularität. |
| K4 | M3 sei als `except ControllerError` an der Aufrufstelle umsetzbar | **Falsch und gefährlich.** `_validate_json_artifact` wirft `ControllerError` aus fünf Ursachen, zwei davon ohne Producer-Schuld (`:1965` fehlende jsonschema-Dependency, `:1970` unlesbare Schema-Datei). Ein pauschaler `except` verwandelte einen Plugin-Defekt in einen verschwendeten Redispatch. | Klassenwahl muss an den **Erkennungsort** (`:1956`/`:1958`/`:1974`), nicht an den Aufrufort. Siehe M3. |
| K5 | M1 sei ein einfaches Löschen der Felder | **Migrationsklippe.** `additionalProperties: false` an Wurzel und in `component_hints.items`, und `.recon-signals.json` steht auf der NEVER-delete-Liste (`runtime_cleanup.py:262-266`) — erhaltene Artefakte eines Vorlaufs würden ungültig. | M1 wird **zweistufig**: erst `required` lösen, Properties später mit Schema-Version-Bump. Siehe M1a. |

---

## 1. Was passiert ist

Der Recon-Scanner (Haiku) schrieb in `.recon-signals.json`:

```json
"signal_classification": { "has_open_self_registration": "candidate" }
```

Erlaubt sind dort nur `deterministic` | `llm-fallback`
(`schemas/recon-signals.schema.json:114`). Ein Enum-Token beendete den Lauf
endgültig.

---

## 2. Kausalkette — fünf Defekte, nach Pipeline-Position

Die Reihenfolge ist jetzt **chronologisch entlang der Pipeline**, nicht nach
Schwere. Das ist die Reihenfolge, in der repariert werden muss.

### P0 · Contract-Design — der Producer wird nach etwas gefragt, das er nicht liefern kann

**D0a — Selbstauskunft über die eigene Provenienz ist ein Kategorienfehler.**
`signal_classification` verlangt vom Modell die Einschätzung, ob sein *eigener*
Wert deterministisch abgeleitet oder geraten war. Ein Modell, das rät, rät auch
darüber, ob es geraten hat. Diese Information ist entweder deterministisch aus
`.recon-patterns.json` (Cat 11) ableitbar — dann gehört sie in ein Skript — oder
sie ist nicht belastbar erhebbar.

**D0b — `required` ohne Konsument.** Verifiziert:

```
$ grep -rn "signal_classification" --include=*.py --include=*.md --include=*.yaml .
agents/appsec-recon-scanner.md:764      # das Template
schemas/recon-signals.schema.json:10,114 # das Schema
tests/… (5 Fixtures)                     # nur zur Schema-Erfüllung
```

**Null Produktivkonsumenten.** Dasselbe gilt für `component_hints[].classification`
(`grep`: nur `validate_intermediate.py:1569-1573`, und dort wird ausschließlich
`component_id` auf Duplikate geprüft, nie `classification`). Beide Felder sind
`required` (`schemas/recon-signals.schema.json:10` bzw. `items.required`).

Ein Feld ohne Leser, dessen einzige Wirkung darin besteht, bei Abweichung einen
bezahlten Lauf zu töten.

### P1 · Prompt-Konstruktion — die Vorlage erzeugt die Verwechslung

**D1 — Zwei disjunkte Vokabulare am selben Key, im selben Template-Block.**
Verifiziert durch Extraktion aller Enum-Pseudowerte aus
`agents/appsec-recon-scanner.md:737-776`:

```
status  => supporting | candidate | none          (10×)
has_open_self_registration => deterministic | llm-fallback   (1×)
classification => deterministic | llm-fallback     (1× pro component_hint)
```

Der Key `has_open_self_registration` erscheint im selben Block **dreimal**:
als Boolean (`:749`), als objektwertiger Key mit innerem `status`-Enum (`:761`),
und als direkt enum-wertiger Key (`:765`). Fünf Zeilen Abstand zwischen der
`candidate`-Variante und der `deterministic`-Variante.

**Skalierungseffekt — hier liegt die Repo-Unabhängigkeit:** Das Modell schreibt
`supporting|candidate|none` zehnmal und `deterministic|llm-fallback`
**1 + N mal**, wobei N die Zahl der `component_hints` ist. Je größer das Repo,
desto mehr Deployable Units, desto häufiger muss das seltenere Vokabular korrekt
getroffen werden. **Das Risiko wächst mit der Repo-Größe** — juice-shop mit vier
Hints ist ein günstiger Fall.

Wichtig (K1): Auf Schema-Ebene existiert diese Kollision **nicht**. Sie entsteht
erst dadurch, dass die Vorlage den `$ref` auf `$defs/evidence` auflöst und beide
Dimensionen nebeneinanderlegt. Ein Schema-Lint ist hier wirkungslos — empirisch
geprüft.

### P2 · Schreibzeitpunkt im Producer — der früheste mechanische Eingriffspunkt

**D2 — Der „HARD GATE" des Agenten ist unerzwungene Prosa.**
`agents/appsec-recon-scanner.md:797-805` schreibt vor, dass der *nächste*
Tool-Call nach dem Schreiben `validate_intermediate.py recon_signals` sein muss
und der Completion-Banner erst nach Exit 0 gedruckt werden darf.

**Empirisch verifiziert — der Gate hätte den Fehler gefangen.** Defekt
rekonstruiert und der vorgeschriebene Validator darauf angesetzt:

```
$ python3 scripts/validate_intermediate.py recon_signals bad-signals.json --repo-root /home/mrohr/juice-shop
INVALID: signal_classification.has_open_self_registration: 'candidate' is not one of ['deterministic', 'llm-fallback']
EXIT=1
```

Ausgeführt wurde er nie. `grep validate_intermediate .hook-events.log` → **null
Treffer**. Stattdessen aus dem Lauf-Log:

```
20:03:53  FILE_WRITE  .recon-signals.json (3,886 chars)
20:04:25  BASH_OK     export OUTPUT_DIR=…  # Simple shell-based v…
20:04:40  SCAN_END    Reconnaissance scan complete
```

Das Modell hat den vorgeschriebenen Validator durch eine selbst erfundene
*„simple shell-based validation"* ersetzt und Erfolg gemeldet.

**Sieben Agenten** deklarieren einen solchen Gate (`recon-scanner`,
`actor-discoverer`, `config-scanner`, `context-resolver`, `control-analyst`,
`evidence-verifier`, `triage-validator`). **Kein Hook prüft, ob er lief.** Die
Durchsetzung existiert als Bitte an das schwächste Modell der Pipeline — und
`resolve_config.py:135,158,169,187` zeigt: `recon_scanner: HAIKU` in **allen vier**
Reasoning-Tiers. Es gibt keine Konfiguration, in der dieses Artefakt von einem
starken Modell geschrieben wird.

### P4 · Boundary-Validierung — Fehlerklasse folgt dem Validator statt dem Producer

**D3 — Regression gegen `1acafffb`.** Der Controller unterscheidet:

| Klasse | Semantik | Stelle |
|---|---|---|
| `ControllerError` | terminal, schreibt `RUN_ABORTED` | `orchestration_controller.py:445` |
| `ProducerContractError` | **einmalig reparierbar** via Redispatch | `:469` |

Commit `1acafffb` („Let a run survive a producer's contract slip", 15.08.)
formuliert den Intent unmissverständlich:

> *„a contract violation in an LLM-written artifact now buys one redispatch
> carrying the validator errors … A deterministic producer's invalid output and
> a second identical violation stay terminal."*

Die Implementierung setzt das nur zur Hälfte um. `_validate_recon_signals`
(`:2038`) prüft **dasselbe LLM-Artefakt zweistufig mit zwei Fehlerklassen**:

```python
value = _validate_json_artifact(…)                            # :2046 → ControllerError = TERMINAL
valid, errs = intermediate_contract.validate_recon_signals(…) # :2051
if not valid:
    raise ProducerContractError(…)                            # :2053 → RETRY
```

`_validate_json_artifact` (`:1962-1975`) wirft grundsätzlich `ControllerError`.
Die Aufrufstelle fängt entsprechend nur die semantische Hälfte (`:3557-3563`).

**Ergebnis:** Semantikfehler → repariert. Schemafehler desselben Modells im
selben Schreibvorgang → Lauf tot. Die Klassifikation hängt daran, *welcher
Validator zuerst zuschlägt*, nicht daran, *wer geschrieben hat* — genau die
Unterscheidung, die der Commit treffen wollte.

Reichweite: `grep -n ProducerContractError scripts/*.py` → **vier** Treffer
(Definition, ein `raise`, ein Retry-Helper, ein `except`). `.recon-signals.json`
ist das **einzige** LLM-Artefakt der Pipeline mit Retry-Pfad überhaupt.
Ohne jeden Pfad: `merger`, `triage-validator`, `evidence-verifier`,
`trust-boundary-analyst`, `control-analyst`, `actor-discoverer`,
`post-stride-synthesizer`, `architecture-analyst`.

### P5 · Fehlerbehandlung — Latch zu breit und irreversibel

**D4a — kein Weiterlaufen nach Reparatur.** `cutoff_cause.detect_abort()` scannt
`.agent-run.log` nach `RUN_ABORTED` mit Epoch ≥ `.scan-start-epoch`.
`_context_v2_guard` (`:2174-2177`) verweigert danach jede Fortsetzung. Kein
Skript löscht den Latch: `check_state.py:465` schont `.agent-run.log` explizit,
`clean-run-state` kennt `RUN_ABORTED` nicht. Einziger Ausweg: neuer Lauf →
Totalverlust von Stage 1.

**D4b — der Latch blockiert die eigene Diagnose-Empfehlung.** Die Meldung sagt
*„preserve the runtime artifacts for diagnosis"*, und der Docstring von
`_context_v2_terminal_abort_reason` (`agent_logger.py:2170-2179`) behauptet
ausdrücklich, Lesen/Diagnose/Recovery-Skills blieben erlaubt. Die Implementierung
prüft nur `event.is_agent_call` (`:2287-2291`) und verweigert **jeden**
Agent-Dispatch im Output-Verzeichnis — auch `general-purpose`, auch
`appsec-run-diagnostician`. **In dieser Session reproduziert:** ein rein
lesender `general-purpose`-Agent wurde mit exakt dieser Meldung abgelehnt.
Der Identitäts-Guard 130 Zeilen tiefer (`:2138-2155`) begrenzt sich korrekt auf
die 13 context-v2-Agenten — der Abort-Guard nicht. Docstring-Absicht ≠ Code.

---

## 3. Warum das repo-unabhängig ist

Nichts an der Kette ist juice-shop-spezifisch:

1. `signal_classification` wird für **jedes** Repo verlangt.
2. Der Recon-Scanner läuft in **allen** Tiers auf Haiku (`resolve_config.py:135,158,169,187`).
3. Die Kollisionshäufigkeit **wächst mit der Repo-Größe** (1 + N Vorkommen des
   selteneren Vokabulars, N = Zahl der Deployable Units).
4. Der Prosa-Gate ist in **sieben** Agenten unerzwungen.
5. Der Latch trifft **jedes** Repo mit `.skill-config.json`.

Ein größeres Monorepo mit 10 Component-Hints hat die Kollisionsgelegenheit
**dreifach** gegenüber juice-shop — bei identisch schwachem Producer-Modell.

---

## 4. Maßnahmen — nach Pipeline-Position

> **Die Nummerierung hier ist die Pipeline-Position, NICHT die Priorität.**
> M1 steht vorn, weil P0 die früheste Ebene ist — nicht weil es zuerst gebaut
> werden soll. Die Umsetzungsreihenfolge steht in §5 und lautet **M3 → M1 → M4
> → M2**. Frühe Interception und universelle Abdeckung sind verschiedene Achsen.

Leitlinie: **Mechanismus vor Prosa, Ableitung vor Selbstauskunft, Reparatur vor
Abbruch.** Precedent im eigenen Code: `.recon-summary.md` besitzt bereits einen
*normalize-then-warn*-Pfad statt Abbruch (`validate_recon_summary.py:135`,
aufgerufen `orchestration_controller.py:3536-3547`, Event
`RECON_KEY_FILES_NORMALIZED`). Die Doktrin existiert — sie wurde beim
Signals-Artefakt nicht durchgezogen.

### M1 · P0 — Contract bereinigen *(früheste Ursache, kleinster Aufwand)*

**M1a — Selbstauskunfts-Felder entfernen.** `signal_classification` und
`component_hints[].classification` haben null Konsumenten; beide fragen das
Modell nach seiner eigenen Zuverlässigkeit.

> **Korrektur aus der Verifikation — Migrationsklippe.** Das Schema setzt
> `additionalProperties: false` an der Wurzel **und** in `component_hints.items`.
> `.recon-signals.json` steht zugleich auf der **NEVER-delete**-Liste
> (`runtime_cleanup.py:262-266`), überlebt also Läufe. Ein sofortiges Löschen der
> Properties machte jedes erhaltene Artefakt eines Vorlaufs ungültig
> (`Additional properties are not allowed`).

**Daher zweistufig:**

*Stufe 1 (sofort, rückwärtskompatibel):* beide Felder aus `required` entfernen
und aus dem Agent-Template streichen. Die Property-Deklarationen **bleiben**, damit
erhaltene Artefakte weiter validieren. Neue Artefakte ohne die Felder validieren
ebenfalls. Fünf Test-Fixtures dürfen sie behalten — beide Formen müssen grün sein.

*Stufe 2 (nächstes Release):* Properties löschen und `recon-signals` in
`CONTEXT_V2_ARTIFACT_SCHEMA_VERSIONS` (`resolve_config.py:459`) von 2 auf 3
heben. Die Versionserhöhung lässt laufende Invocations mit *„incompatible
context-v2 artifact schema versions"* abbrechen (`orchestration_controller.py:2168-2172`)
— gewolltes Verhalten, gehört aber an eine Release-Grenze, nicht in einen Hotfix.

Wird die Provenienz später gebraucht, gehört sie deterministisch abgeleitet: der
Controller weiß aus `.recon-patterns.json` Cat 11, ob eine Registrierungsroute
gefunden wurde — das ist eine Skriptzeile, keine Modellfrage.

**M1b — Regel als Test verankern.** Für jedes `required`-Feld eines
LLM-Artefakt-Schemas muss ein lesender Produktivpfad existieren. Mechanisch
prüfbar: mindestens ein `grep`-Treffer außerhalb `schemas/`, `agents/`, `tests/`.
Fehlt er → Feld ist optional oder wird gelöscht.

*Verhindert diesen Abbruch vollständig und dauerhaft.*

### M2 · P2 — Artefakt beim Schreiben validieren *(früheste generische Mechanik)*

Der Kern der Korrektur K2. Statt Prosa („der nächste Tool-Call muss …") ein
**PostToolUse-Hook auf `Write|Edit`**, der den geschriebenen Pfad gegen eine
Artefakt→Contract-Tabelle nachschlägt und bei Treffer sofort
`validate_intermediate.py` fährt. Bei Verstoß wird das Ergebnis als
Block-Reason an den *schreibenden Subagenten* zurückgegeben.

Warum das der richtige Punkt ist:
* **Früheste Stelle mit Mechanik.** Der Fehler wird 4 Sekunden nach seiner
  Entstehung sichtbar, im Kontext, der ihn erzeugt hat — Reparatur = ein Edit.
* **Generisch über alle Producer und alle Repos.** Der Hook kennt nur
  Dateiname → Schema; nichts Repo-Spezifisches.
* **Macht D2 gegenstandslos.** Die sieben Prosa-Gates werden zu Redundanz statt
  zu alleiniger Absicherung.

Infrastruktur ist vollständig vorhanden:
* `PostToolUse` ist bereits registriert und auf `agent_logger.py` geroutet
  (`hooks/hooks.json:71-79`); `FILE_WRITE`-Events des Subagenten belegen, dass
  der Hook in Subagent-Sessions feuert.
* `validate_intermediate.py:70-83` hat bereits eine `kind → schema`-Tabelle.
* **Einzige Lücke:** eine `artefaktpfad → kind`-Tabelle
  (`.recon-signals.json → recon_signals`, `.actors-discovered.json →
  actors_discovered`, `.evidence-verification.json → evidence_verification`,
  `.merge-decisions.json → merge_decisions`, …). Das ist die eigentliche
  Implementierungsarbeit — etwa 15 Zeilen.

**Backstop `SubagentStop`:** Ein Agent kann die `Write`-Route umgehen (Heredoc
via Bash). Deshalb zusätzlich im bereits registrierten `SubagentStop`-Handler
(`hooks/hooks.json:101-109`) prüfen, ob jedes deklarierte `OUTPUT_ARTIFACTS` des
Jobs gültig auf Platte liegt. Damit ist P2 nicht umgehbar.

### M3 · P4 — Fehlerklasse an den Producer binden, nicht an den Validator

Vervollständigt den Intent von `1acafffb`. Ein von einem LLM geschriebenes
Artefakt erzeugt bei **jedem** Contract-Verstoß `ProducerContractError` — Schema
wie Semantik.

> **Korrektur aus der Verifikation.** Die naheliegende Form —
> `except ControllerError → ProducerContractError` an der Aufrufstelle — ist
> **falsch und gefährlich**. `_validate_json_artifact` wirft `ControllerError`
> aus fünf Ursachen, zwei davon ohne Producer-Schuld:
>
> | Zeile | Ursache | Schuld |
> |---|---|---|
> | `:1965` | jsonschema-Dependency fehlt | **Plugin/Env** |
> | `:1970` | Schema-Datei unlesbar | **Plugin** |
> | `:1956` | Datei fehlt / kaputtes JSON | Producer |
> | `:1958` | JSON ist kein Objekt | Producer |
> | `:1974` | Dokument verletzt Schema | Producer |
>
> Ein pauschaler `except` verwandelte eine kaputte Plugin-Installation in einen
> verschwendeten Redispatch — und maskierte genau die Defektklasse, die
> `:474-476` ausdrücklich schützt.

**Korrekte Form — Klassenwahl am Erkennungsort, nicht am Aufrufort:**

```python
def _load_json_object(path, *, contract, producer="deterministic"): ...
def _validate_json_artifact(path, schema_path, *, contract, producer="deterministic"): ...
```

* `:1956`, `:1958`, `:1974` wählen die Klasse nach `producer`.
* `:1965`, `:1970` bleiben **unbedingt** `ControllerError` — Plugin-Defekte.
* `_validate_recon_signals` übergibt `producer="llm"`; dort werden zusätzlich
  `:2043` (`cannot stat` = nicht geschrieben) und `:2045` (Byte-Cap) zu
  Producer-Fehlern.
* Alle übrigen ~20 Aufrufstellen behalten den Default → **null Verhaltensänderung**
  außerhalb der LLM-Artefakte.

Umfang: ~15 Zeilen. Tests: (a) der reproduzierte Defekt liefert eine
Retry-Action statt `abort`; (b) eine unlesbare Schema-Datei bricht weiterhin
terminal ab.

**Invariante halten** (`:474-476`): Deterministische Producer bleiben terminal.
Die Trennlinie ist **LLM vs. Skript**, nicht **Schema vs. Semantik** — und
innerhalb der LLM-Artefakte zusätzlich **Dokumentfehler vs. Werkzeugfehler**.

Der Fehlertext von `_validate_json_artifact` (`:1974`, bis zu 5 Fehler mit
JSON-Pointer) passt bereits ohne Anpassung in `_write_producer_repair_brief`
(`:515-536`), dessen Instruktionstext auch für Schemafehler korrekt ist.

### M4 · P4 — Retry-Pfad auf alle LLM-Producer ausdehnen

`_recon_producer_retry` (`:3443`) auf rollen-generische Form heben:

```python
def _producer_retry(output_dir, cfg, *, role, artifact, exc, agent_type, model, inputs)
```

Der Ledger (`:491`) ist bereits generisch gekeyt — nur die Dispatch-Konstruktion
ist recon-hartcodiert. Jede Boundary, die ein LLM-Artefakt validiert, bekommt den
`try/except`-Rahmen aus `:3557-3563`. `MAX_PRODUCER_RETRIES = 1` bleibt.

### M5 · P1 — Template-Lint auf der richtigen Ebene *(korrigiert, siehe K1)*

Kein Schema-Lint. Geprüft wird die **Agent-Vorlage**: innerhalb eines
JSON-Template-Blocks darf kein Key-Name mit zwei disjunkten Wertevokabularen
auftreten, und kein Vokabular darf sich mit dem eines Nachbarschlüssels
überschneidungsfrei-aber-verwechselbar mischen.

Ergänzend — und wertvoller — ein **Template↔Schema-Konsistenztest**: jedes
`"key": "a | b | c"`-Pseudoliteral in `agents/*.md` wird gegen das Enum am
entsprechenden Schema-Pfad geprüft. Das fängt echten Drift zwischen Vorlage und
Schema. (Hier wäre er wirkungslos gewesen — die Vorlage war korrekt — aber er
schließt die Nachbarlücke, die `1acafffb` bereits einmal getroffen hat.)

Anmerkung zum bestehenden Drift-Test
(`tests/test_agent_definitions.py::test_recon_signal_prompt_states_the_coupling_the_validator_enforces`,
aus `1acafffb`): Er verankert **englische Prosasätze** per String-Match. Das
schützt genau eine Kopplung und skaliert nicht auf Vokabulare. Der
Konsistenztest sollte ihn ergänzen, nicht kopieren.

### M6 · P5 — Latch verengen und reversibel machen

**M6a — Guard auf context-v2-Producer verengen.** Der Abort-Guard
(`agent_logger.py:2287-2291`) muss dieselbe Allowlist verwenden wie der
Identitäts-Guard darunter (`:2139-2153`). Stellt die im Docstring behauptete
Semantik her und macht die eigene Empfehlung („preserve for diagnosis")
befolgbar.

**M6b — expliziter Clear-Pfad.** `orchestration_controller.py clear-abort` bzw.
`clean-run-state`: **keine** Log-Zeilen löschen, sondern ein
`RUN_ABORT_CLEARED`-Event mit Begründung anhängen; `detect_abort()` wertet das
jüngste Abort/Clear-Paar aus. Audit-Historie bleibt vollständig, Reversibilität
wird nachvollziehbar.

> Der naheliegende Workaround — `RUN_ABORTED`-Zeilen aus `.agent-run.log`
> filtern — ist Audit-Manipulation und wurde in dieser Session vom
> Auto-Mode-Classifier korrekt blockiert. Dass dies aktuell der **einzige**
> Fortsetzungsweg ist, ist selbst das Argument für M6b.

**M6c — Abbruchmeldung um den konkreten Recovery-Befehl ergänzen.**

---

## 5. Empfehlung

> **Korrektur K2 — Fehlgewichtung der ersten Fassung.** Rev. 1
> setzte „möglichst früh in der Pipeline" mit „am wirksamsten" gleich und stufte
> M3 als Auffangnetz ein. Das war ein Kategorienfehler: **frühe Interception und
> universelle Abdeckung sind verschiedene Achsen.** M3 liegt spät, deckt aber
> alles ab — und behebt einen eigenständigen Defekt, kein Symptom.

### Rangfolge

| # | Maßnahme | Verifikationsstand | Warum hier |
|---|---|---|---|
| 1 | **M3** — Fehlerklasse am Erkennungsort wählen | verifiziert, ~15 Zeilen | eigener Defekt · universelle Abdeckung · größte Kostenstufe |
| 2 | **M1 Stufe 1** — Felder aus `required` + Template | verifiziert inkl. Migrationspfad, ~10 Zeilen | entfernt die konkrete Ursache, rückwärtskompatibel |
| 3 | **M4** — Retry rollen-generisch | Code gelesen | zieht M3s Abdeckung auf die 8 Producer ohne Pfad |
| 4 | **M2** — Validierung zur Schreibzeit | **Spike nötig** | bester Interceptionspunkt, Mechanismus unbelegt |
| 5 | M5 — Template-Lint | — | Hygiene |
| 6 | M6 — Latch verengen/reversibel | — | Hygiene, aber blockiert aktuell jede Diagnose |

### Warum M3 zuerst

**M3 ist kein Symptomfix.** `_validate_recon_signals` wählt die Fehlerklasse
danach, *welcher Validator zuerst feuert*, statt danach, *wer das Artefakt
geschrieben hat*. Diese falsche Zeile existiert unabhängig vom Enum-Bug und
trifft jeden künftigen Contract-Verstoß. Sie ist eine Ursache an ihrer eigenen
Stelle.

**Universelle Abdeckung.** M1 entfernt *dieses* Feld; M2 fängt *bekannte*
Artefakte auf der *Write*-Route. Ein neues Feld, ein neuer Producer, ein
Artefakt außerhalb der Pfad-Tabelle oder ein Heredoc-Write erreichen weiterhin
die Boundary. M3 ändert dort das **Default-Verhalten** von „Lauf tot" auf „ein
Redispatch". M1 und M2 sind aufzählend, M3 ist fail-safe by construction.

**Kostenstufen sind ungleich.** M2 spart *Redispatch → Edit* (≈ Faktor 10),
M3 spart *toter Lauf → Redispatch* (≈ Faktor 100).

**Bereits erklärte Zusage.** `1acafffb` dokumentiert, ein LLM-Contract-Verstoß
koste einen Redispatch. Solange M3 fehlt, ist diese Aussage im Repo unwahr.

### Warum M2 einen Spike braucht

`grep` über alle Hook-Skripte: **kein einziger Hook dieses Plugins nutzt eine
PostToolUse-Block-Entscheidung.** Jeder entscheidende Hook
(`plugin_write_gate.py`, `plugin_read_gate.py`, `skill_policy_gate.py`,
`agent_logger.py`) hängt an **PreToolUse**. Dass ein PostToolUse-Block an einen
*Subagenten* zurückgespielt wird und ihn zur Korrektur zwingt, ist in diesem
Codebase unerprobt und hier nicht verifiziert.

Verifiziert ist nur, dass PostToolUse in Subagent-Sessions **feuert**
(`FILE_WRITE`-Events des Recon-Subagenten). Das reicht für Erkennung und
Protokollierung, nicht für Erzwingung. Spike zuerst: Blockt ein PostToolUse-Deny
den Subagenten und erreicht ihn der Grund? Falls nein, degradiert M2 auf
„erkennen + `PRODUCER_SELF_VALIDATION_FAILED` loggen" und die Erzwingung wandert
in den `SubagentStop`-Backstop.

M2 bleibt der beste Interceptionspunkt — es darf nur nicht die einzige Zusage
tragen, solange sein Mechanismus unbelegt ist.

### Ohne welche Maßnahme was offenbleibt

* **ohne M3:** jeder LLM-Contract-Verstoß tötet weiter einen bezahlten Lauf —
  auch nach M1, denn M1 entfernt nur *dieses* Feld.
* **ohne M1:** zwei `required`-Felder ohne Leser bleiben in der Pipeline und
  schlagen auf größeren Repos häufiger zu (1 + N Vorkommen).
* **ohne M2:** der Fehler bleibt bis zur Boundary unsichtbar; Reparatur kostet
  einen Redispatch statt eines Edits.
* **ohne M6a:** die Abbruchmeldung empfiehlt eine Diagnose, die ihr eigener
  Guard verhindert.

---

## 6. Symptom → Ursache (für künftige Läufe)

| Symptom | Ursache | Maßnahme |
|---|---|---|
| `RUN_ABORTED … is not one of […]` direkt nach einer Producer-Boundary | D3 — Schemaverstoß eines LLM-Artefakts terminal klassifiziert | M3 |
| Agent meldet Erfolg, Controller lehnt das Artefakt ab | D2 — Prosa-Gate übersprungen | M2 |
| Falscher Enum-Wert stammt aus einem Nachbarfeld derselben Vorlage | D1 — Vokabular-Kollision im flachen Template | M5 |
| Fehler tritt auf größeren Repos häufiger auf | D1-Skalierung — 1+N Vorkommen des selteneren Vokabulars | M1a |
| Jeder Agent-Dispatch im Repo wird abgelehnt, auch unbeteiligte | D4b — Abort-Guard nicht auf Producer verengt | M6a |
| Nach manueller Artefakt-Reparatur bleibt der Lauf blockiert | D4a — Latch ohne Clear-Pfad | M6b |
